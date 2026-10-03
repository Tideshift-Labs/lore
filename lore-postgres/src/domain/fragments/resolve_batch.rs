// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! Coalesces concurrent resolves into one statement (WP-115 row 79, INV-FU).
//!
//! Every fragment GET resolves its one hash twice, before and after the read,
//! and each resolve used to check out its own domain connection for one
//! statement. Under clone load that was 65% of all domain checkouts, with the
//! connection held 1.31 ms for a 0.04 ms statement: the round trips, not the
//! query, were the cost.
//!
//! The resolver statement already takes many `(hash, context)` pairs and
//! answers each by ordinal, so concurrent callers can share it. A caller
//! queues its request under its repository and waits for its own answer. A
//! drain task per repository (at most [`MAX_RESOLVE_BATCHES_PER_REPOSITORY`])
//! checks out a connection, and only once it holds one takes whatever is
//! queued, up to [`MAX_RESOLVE_BATCH_HASHES`] hashes, into one statement. So
//! batching adds no timer: at low load a request runs alone at once, and under
//! load the batch is whatever queued while the pool was busy.
//!
//! **What each caller sees is unchanged.** One statement is one snapshot, as
//! it was for each caller alone; the statement scopes every request by its own
//! ordinal and context; and a row that fails to decode fails only the request
//! that owns it. A statement or checkout failure fails every request in that
//! batch, which is what each would have seen on its own connection.
//!
//! **Cancelling a caller cancels nothing else.** The drain runs as its own
//! task, so dropping a waiter drops only its reply channel. A request whose
//! waiter is already gone is skipped when a batch is taken; one dropped after
//! that is answered into a closed channel.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::future::Future;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::PoisonError;

use tokio::sync::oneshot;

use super::FragmentQueryRequest;
use super::ScopedFragmentResolution;
use crate::domain::errors::DomainError;
use crate::pool::Pool;
use crate::pool::PooledClient;

/// Most hashes one batched statement carries. A call with this many or more
/// runs alone on its own checkout.
pub(super) const MAX_RESOLVE_BATCH_HASHES: usize = 64;

/// Most drain tasks, and so most connections, one repository's resolves hold
/// at once.
pub(super) const MAX_RESOLVE_BATCHES_PER_REPOSITORY: usize = 2;

/// One request's answer from a statement, or the error decoding its row.
pub(super) type RequestOutcome = Result<ScopedFragmentResolution, DomainError>;

type Reply = Result<Vec<ScopedFragmentResolution>, DomainError>;

/// Where a batch runs: a checkout, then one statement on it.
pub(super) trait ResolveExecutor: Send + Sync + 'static {
    type Connection: Send + Sync;

    fn connect(&self) -> impl Future<Output = Result<Self::Connection, DomainError>> + Send;

    /// One outcome per request per hash, in order.
    fn run(
        &self,
        connection: &Self::Connection,
        repository_id: &[u8],
        requested: &[FragmentQueryRequest],
    ) -> impl Future<Output = Result<Vec<RequestOutcome>, DomainError>> + Send;
}

/// The production executor: the coordinator's pool and resolver statement.
pub(super) struct PooledResolver {
    pool: Pool,
}

impl PooledResolver {
    pub(super) fn new(pool: Pool) -> Self {
        Self { pool }
    }
}

impl ResolveExecutor for PooledResolver {
    type Connection = PooledClient;

    fn connect(&self) -> impl Future<Output = Result<PooledClient, DomainError>> + Send {
        // The checkout site is this line, so batched resolves are counted
        // apart from the unbatched ones in `resolve_scoped`.
        let checkout = self.pool.get();
        async move {
            checkout
                .await
                .map_err(|error| DomainError::from_pool("fragment coordinator pool", error))
        }
    }

    fn run(
        &self,
        connection: &PooledClient,
        repository_id: &[u8],
        requested: &[FragmentQueryRequest],
    ) -> impl Future<Output = Result<Vec<RequestOutcome>, DomainError>> + Send {
        super::run_resolve_statement(connection, repository_id, requested)
    }
}

struct Pending {
    requested: Vec<FragmentQueryRequest>,
    reply: oneshot::Sender<Reply>,
}

#[derive(Default)]
struct RepositoryQueue {
    pending: VecDeque<Pending>,
    drains: usize,
}

pub(super) struct ResolveBatcher<E> {
    executor: E,
    repositories: Mutex<HashMap<Vec<u8>, RepositoryQueue>>,
}

impl<E: ResolveExecutor> ResolveBatcher<E> {
    pub(super) fn new(executor: E) -> Self {
        Self {
            executor,
            repositories: Mutex::new(HashMap::new()),
        }
    }

    /// Resolve `requested` in `repository_id`, sharing a statement with
    /// whatever else is queued for that repository.
    pub(super) async fn resolve(
        self: &Arc<Self>,
        repository_id: &[u8],
        requested: Vec<FragmentQueryRequest>,
    ) -> Reply {
        let (reply, answer) = oneshot::channel();
        let start_drain = {
            let mut repositories = self.lock();
            let queue = repositories.entry(repository_id.to_vec()).or_default();
            queue.pending.push_back(Pending { requested, reply });
            if queue.drains < MAX_RESOLVE_BATCHES_PER_REPOSITORY {
                queue.drains += 1;
                true
            } else {
                false
            }
        };
        if start_drain {
            let batcher = Arc::clone(self);
            let repository_id = repository_id.to_vec();
            drop(lore_base::lore_spawn!(
                "fragment-resolve-batch",
                batcher.drain(repository_id)
            ));
        }
        answer.await.map_err(|_closed| {
            DomainError::Internal("fragment resolve batch ended without an answer".to_owned())
        })?
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<Vec<u8>, RepositoryQueue>> {
        self.repositories
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    async fn drain(self: Arc<Self>, repository_id: Vec<u8>) {
        let mut slot = DrainSlot {
            batcher: &self,
            repository_id: &repository_id,
            held: true,
        };
        // Stop, giving the slot back, when nothing is queued: checked before
        // the checkout so an idle drain never takes a connection.
        while slot.keep_if_pending() {
            let connection = self.executor.connect().await;
            let batch = self.take_batch(&repository_id);
            if batch.is_empty() {
                // The other drain took it while this one waited.
                continue;
            }
            match connection {
                Ok(connection) => self.answer(&connection, &repository_id, batch).await,
                Err(error) => fail(batch, &error),
            }
        }
    }

    /// The front of the queue, up to the hash bound, skipping requests whose
    /// waiter has gone. Always at least one live request if any is queued.
    fn take_batch(&self, repository_id: &[u8]) -> Vec<Pending> {
        let mut repositories = self.lock();
        let Some(queue) = repositories.get_mut(repository_id) else {
            return Vec::new();
        };
        let mut batch = Vec::new();
        let mut hashes = 0_usize;
        while let Some(next) = queue.pending.front() {
            if next.reply.is_closed() {
                queue.pending.pop_front();
                continue;
            }
            if !batch.is_empty() && hashes + next.requested.len() > MAX_RESOLVE_BATCH_HASHES {
                break;
            }
            hashes += next.requested.len();
            if let Some(next) = queue.pending.pop_front() {
                batch.push(next);
            }
        }
        batch
    }

    async fn answer(&self, connection: &E::Connection, repository_id: &[u8], batch: Vec<Pending>) {
        let requested = batch
            .iter()
            .flat_map(|pending| pending.requested.iter().cloned())
            .collect::<Vec<_>>();
        let outcomes = match self
            .executor
            .run(connection, repository_id, &requested)
            .await
        {
            Ok(outcomes) if outcomes.len() == requested.len() => outcomes,
            Ok(outcomes) => {
                let error = DomainError::Internal(format!(
                    "fragment resolver answered {} of {} requests",
                    outcomes.len(),
                    requested.len()
                ));
                fail(batch, &error);
                return;
            }
            Err(error) => {
                fail(batch, &error);
                return;
            }
        };
        let mut outcomes = outcomes.into_iter();
        for pending in batch {
            let answer = outcomes
                .by_ref()
                .take(pending.requested.len())
                .collect::<Result<Vec<_>, _>>();
            drop(pending.reply.send(answer));
        }
    }
}

/// Answer every request in `batch` with `error`.
fn fail(batch: Vec<Pending>, error: &DomainError) {
    for pending in batch {
        drop(pending.reply.send(Err(error.clone())));
    }
}

/// One drain's claim on its repository's drain count. Given back when the
/// drain finds the queue empty, or when the drain ends any other way (a
/// panic in the statement), so a repository can never be left with a count
/// and no drain behind it.
struct DrainSlot<'a, E: ResolveExecutor> {
    batcher: &'a ResolveBatcher<E>,
    repository_id: &'a [u8],
    held: bool,
}

impl<E: ResolveExecutor> DrainSlot<'_, E> {
    /// True if work is queued. If not, gives the slot back in the same lock,
    /// so a request queued after this sees the free slot and starts a drain.
    fn keep_if_pending(&mut self) -> bool {
        let mut repositories = self.batcher.lock();
        let pending = repositories
            .get(self.repository_id)
            .is_some_and(|queue| !queue.pending.is_empty());
        if !pending {
            release(&mut repositories, self.repository_id);
            self.held = false;
        }
        pending
    }
}

impl<E: ResolveExecutor> Drop for DrainSlot<'_, E> {
    fn drop(&mut self) {
        if self.held {
            release(&mut self.batcher.lock(), self.repository_id);
        }
    }
}

/// Give back one drain slot. The last drain out drops anything still queued,
/// whose waiters then see an error rather than waiting for a drain that will
/// never come; normally nothing is queued here.
fn release(repositories: &mut HashMap<Vec<u8>, RepositoryQueue>, repository_id: &[u8]) {
    let Some(queue) = repositories.get_mut(repository_id) else {
        return;
    };
    queue.drains = queue.drains.saturating_sub(1);
    if queue.drains == 0 {
        repositories.remove(repository_id);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use tokio::sync::OwnedSemaphorePermit;
    use tokio::sync::Semaphore;

    use super::*;
    use crate::domain::fragments::FragmentResolution;
    use crate::domain::fragments::FragmentVerdict;

    /// A hash whose row the fake cannot decode.
    const POISON: u8 = 0xEE;

    /// A pool of `Semaphore` permits and a statement that records its batch.
    struct Fake {
        pool: Arc<Semaphore>,
        /// Each statement takes and returns one permit, so a test can hold a
        /// batch in flight.
        statement: Arc<Semaphore>,
        connects: AtomicUsize,
        batches: Mutex<Vec<(Vec<u8>, Vec<FragmentQueryRequest>)>>,
        fail_statement: AtomicBool,
        panic_statement: AtomicBool,
    }

    impl ResolveExecutor for Fake {
        type Connection = OwnedSemaphorePermit;

        fn connect(
            &self,
        ) -> impl Future<Output = Result<OwnedSemaphorePermit, DomainError>> + Send {
            self.connects.fetch_add(1, Ordering::SeqCst);
            let pool = Arc::clone(&self.pool);
            async move {
                pool.acquire_owned()
                    .await
                    .map_err(|_closed| DomainError::Transient("fake pool closed".to_owned()))
            }
        }

        fn run(
            &self,
            _connection: &OwnedSemaphorePermit,
            repository_id: &[u8],
            requested: &[FragmentQueryRequest],
        ) -> impl Future<Output = Result<Vec<RequestOutcome>, DomainError>> + Send {
            self.batches
                .lock()
                .unwrap()
                .push((repository_id.to_vec(), requested.to_vec()));
            let statement = Arc::clone(&self.statement);
            let fail = self.fail_statement.load(Ordering::SeqCst);
            let panic = self.panic_statement.load(Ordering::SeqCst);
            let repository_id = repository_id.to_vec();
            let requested = requested.to_vec();
            async move {
                drop(statement.acquire().await.unwrap());
                assert!(!panic, "fake resolver statement panicked");
                if fail {
                    return Err(DomainError::Transient("fake statement failed".to_owned()));
                }
                Ok(requested
                    .iter()
                    .map(|request| {
                        if request.hash.first() == Some(&POISON) {
                            Err(DomainError::Internal("fake undecodable row".to_owned()))
                        } else {
                            Ok(expected(&repository_id, request))
                        }
                    })
                    .collect())
            }
        }
    }

    /// What the fake answers for one request: a function of the repository,
    /// hash and context, so a misrouted answer cannot pass.
    fn expected(repository_id: &[u8], request: &FragmentQueryRequest) -> ScopedFragmentResolution {
        ScopedFragmentResolution {
            resolution: FragmentResolution {
                hash: request.hash.clone(),
                verdict: FragmentVerdict::Absent,
            },
            exact_context_readable: request.context.first() == repository_id.first(),
        }
    }

    fn batcher(pool_permits: usize) -> Arc<ResolveBatcher<Fake>> {
        Arc::new(ResolveBatcher::new(Fake {
            pool: Arc::new(Semaphore::new(pool_permits)),
            statement: Arc::new(Semaphore::new(Semaphore::MAX_PERMITS)),
            connects: AtomicUsize::new(0),
            batches: Mutex::new(Vec::new()),
            fail_statement: AtomicBool::new(false),
            panic_statement: AtomicBool::new(false),
        }))
    }

    fn request(hash: u8, context: u8) -> FragmentQueryRequest {
        FragmentQueryRequest {
            hash: vec![hash; 32],
            context: vec![context; 16],
        }
    }

    fn spawn_resolve(
        batcher: &Arc<ResolveBatcher<Fake>>,
        repository_id: &[u8],
        requested: Vec<FragmentQueryRequest>,
    ) -> tokio::task::JoinHandle<Reply> {
        let batcher = Arc::clone(batcher);
        let repository_id = repository_id.to_vec();
        lore_base::lore_spawn!(async move { batcher.resolve(&repository_id, requested).await })
    }

    fn queued(batcher: &ResolveBatcher<Fake>, repository_id: &[u8]) -> usize {
        batcher
            .lock()
            .get(repository_id)
            .map_or(0, |queue| queue.pending.len())
    }

    async fn eventually(what: &str, condition: impl Fn() -> bool) {
        for _ in 0..2_000 {
            if condition() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        panic!("timed out waiting until {what}");
    }

    fn batches(batcher: &ResolveBatcher<Fake>) -> Vec<(Vec<u8>, Vec<FragmentQueryRequest>)> {
        batcher.executor.batches.lock().unwrap().clone()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn one_resolve_at_low_load_runs_alone_on_one_checkout() {
        let batcher = batcher(1);
        let repository = vec![7_u8; 16];
        let asked = vec![request(1, 7)];
        let answer = batcher.resolve(&repository, asked.clone()).await.unwrap();
        assert_eq!(answer, vec![expected(&repository, &asked[0])]);
        eventually("the drain gives its slot back", || {
            batcher.lock().is_empty()
        })
        .await;
        assert_eq!(batcher.executor.connects.load(Ordering::SeqCst), 1);
        assert_eq!(batches(&batcher).len(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_single_hash_resolves_share_one_statement() {
        let batcher = batcher(0);
        let repository = vec![7_u8; 16];
        let asked = (0..20_u8)
            .map(|index| request(index, if index % 2 == 0 { 7 } else { 9 }))
            .collect::<Vec<_>>();
        let waiters = asked
            .iter()
            .map(|one| spawn_resolve(&batcher, &repository, vec![one.clone()]))
            .collect::<Vec<_>>();
        eventually("all 20 are queued", || queued(&batcher, &repository) == 20).await;
        batcher.executor.pool.add_permits(1);
        for (waiter, one) in waiters.into_iter().zip(&asked) {
            assert_eq!(
                waiter.await.unwrap().unwrap(),
                vec![expected(&repository, one)]
            );
        }
        assert_eq!(batches(&batcher).len(), 1, "one statement answers all 20");
        eventually("both drains give their slots back", || {
            batcher.lock().is_empty()
        })
        .await;
        assert!(
            batcher.executor.connects.load(Ordering::SeqCst) <= MAX_RESOLVE_BATCHES_PER_REPOSITORY
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_batch_never_carries_more_than_the_hash_bound() {
        let batcher = batcher(0);
        let repository = vec![7_u8; 16];
        let waiters = (0..150_u32)
            .map(|index| {
                let mut one = request(0, 7);
                one.hash[..4].copy_from_slice(&index.to_le_bytes());
                spawn_resolve(&batcher, &repository, vec![one])
            })
            .collect::<Vec<_>>();
        eventually("all 150 are queued", || {
            queued(&batcher, &repository) == 150
        })
        .await;
        batcher.executor.pool.add_permits(1);
        for waiter in waiters {
            assert_eq!(waiter.await.unwrap().unwrap().len(), 1);
        }
        let sizes = batches(&batcher)
            .iter()
            .map(|(_, requested)| requested.len())
            .collect::<Vec<_>>();
        assert!(
            sizes.iter().all(|size| *size <= MAX_RESOLVE_BATCH_HASHES),
            "{sizes:?}"
        );
        assert_eq!(sizes.iter().sum::<usize>(), 150);
        assert_eq!(sizes.len(), 3, "{sizes:?}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_undecodable_row_fails_only_the_request_that_owns_it() {
        let batcher = batcher(0);
        let repository = vec![7_u8; 16];
        let first = vec![request(1, 7)];
        let poisoned = vec![request(2, 7), request(POISON, 7)];
        let last = vec![request(3, 9), request(4, 7)];
        let waiters = [first.clone(), poisoned, last.clone()]
            .into_iter()
            .map(|asked| spawn_resolve(&batcher, &repository, asked))
            .collect::<Vec<_>>();
        eventually("all three are queued", || {
            queued(&batcher, &repository) == 3
        })
        .await;
        batcher.executor.pool.add_permits(1);
        let mut answers = Vec::new();
        for waiter in waiters {
            answers.push(waiter.await.unwrap());
        }
        assert_eq!(batches(&batcher).len(), 1);
        assert_eq!(
            answers[0],
            Ok(first.iter().map(|one| expected(&repository, one)).collect())
        );
        assert_eq!(
            answers[1],
            Err(DomainError::Internal("fake undecodable row".to_owned()))
        );
        assert_eq!(
            answers[2],
            Ok(last.iter().map(|one| expected(&repository, one)).collect())
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_statement_failure_fails_every_request_in_its_batch() {
        let batcher = batcher(0);
        batcher
            .executor
            .fail_statement
            .store(true, Ordering::SeqCst);
        let repository = vec![7_u8; 16];
        let waiters = (1..=3_u8)
            .map(|hash| spawn_resolve(&batcher, &repository, vec![request(hash, 7)]))
            .collect::<Vec<_>>();
        eventually("all three are queued", || {
            queued(&batcher, &repository) == 3
        })
        .await;
        batcher.executor.pool.add_permits(1);
        for waiter in waiters {
            assert_eq!(
                waiter.await.unwrap(),
                Err(DomainError::Transient("fake statement failed".to_owned()))
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_cancelled_waiter_cancels_neither_its_batch_nor_its_neighbours() {
        let batcher = batcher(0);
        batcher
            .executor
            .statement
            .forget_permits(Semaphore::MAX_PERMITS);
        let repository = vec![7_u8; 16];
        let asked = (1..=3_u8).map(|hash| request(hash, 7)).collect::<Vec<_>>();
        let mut waiters = asked
            .iter()
            .map(|one| spawn_resolve(&batcher, &repository, vec![one.clone()]))
            .collect::<Vec<_>>();
        eventually("all three are queued", || {
            queued(&batcher, &repository) == 3
        })
        .await;
        batcher.executor.pool.add_permits(1);
        eventually("the batch is in flight", || batches(&batcher).len() == 1).await;

        // Cancel one waiter inside the running batch, and one queued behind it.
        waiters.remove(0).abort();
        let skipped = spawn_resolve(&batcher, &repository, vec![request(4, 7)]);
        eventually("one more is queued", || queued(&batcher, &repository) == 1).await;
        let behind = spawn_resolve(&batcher, &repository, vec![request(5, 7)]);
        eventually("two more are queued", || queued(&batcher, &repository) == 2).await;
        skipped.abort();
        eventually("the skipped waiter is gone", || {
            batcher.lock().get(&repository).is_some_and(|queue| {
                queue
                    .pending
                    .front()
                    .is_some_and(|front| front.reply.is_closed())
            })
        })
        .await;

        batcher
            .executor
            .statement
            .add_permits(Semaphore::MAX_PERMITS);
        for (waiter, one) in waiters.into_iter().zip(&asked[1..]) {
            assert_eq!(
                waiter.await.unwrap().unwrap(),
                vec![expected(&repository, one)]
            );
        }
        assert_eq!(
            behind.await.unwrap().unwrap(),
            vec![expected(&repository, &request(5, 7))]
        );
        let batches = batches(&batcher);
        assert_eq!(batches.len(), 2);
        let mut running = batches[0].1.clone();
        running.sort_by(|left, right| left.hash.cmp(&right.hash));
        assert_eq!(
            running, asked,
            "the running batch kept its cancelled member"
        );
        assert_eq!(
            batches[1].1,
            vec![request(5, 7)],
            "the cancelled queued request was skipped"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn repositories_never_share_a_statement() {
        let batcher = batcher(0);
        let (left, right) = (vec![7_u8; 16], vec![9_u8; 16]);
        let waiters = [(&left, 1_u8), (&right, 2), (&left, 3), (&right, 4)]
            .into_iter()
            .map(|(repository, hash)| {
                (
                    repository.clone(),
                    hash,
                    spawn_resolve(&batcher, repository, vec![request(hash, 7)]),
                )
            })
            .collect::<Vec<_>>();
        eventually("all four are queued", || {
            queued(&batcher, &left) == 2 && queued(&batcher, &right) == 2
        })
        .await;
        batcher.executor.pool.add_permits(2);
        for (repository, hash, waiter) in waiters {
            assert_eq!(
                waiter.await.unwrap().unwrap(),
                vec![expected(&repository, &request(hash, 7))]
            );
        }
        let batches = batches(&batcher);
        assert_eq!(batches.len(), 2);
        for (repository, requested) in batches {
            let mut hashes = requested.iter().map(|one| one.hash[0]).collect::<Vec<_>>();
            hashes.sort_unstable();
            if repository == left {
                assert_eq!(hashes, vec![1, 3]);
            } else {
                assert_eq!(hashes, vec![2, 4]);
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_panicking_statement_fails_its_waiters_and_frees_the_repository() {
        let batcher = batcher(1);
        batcher
            .executor
            .panic_statement
            .store(true, Ordering::SeqCst);
        let repository = vec![7_u8; 16];
        assert_eq!(
            batcher.resolve(&repository, vec![request(1, 7)]).await,
            Err(DomainError::Internal(
                "fragment resolve batch ended without an answer".to_owned()
            ))
        );
        eventually("the panicked drain gives its slot back", || {
            batcher.lock().is_empty()
        })
        .await;
        batcher
            .executor
            .panic_statement
            .store(false, Ordering::SeqCst);
        assert_eq!(
            batcher.resolve(&repository, vec![request(2, 7)]).await,
            Ok(vec![expected(&repository, &request(2, 7))])
        );
    }
}
