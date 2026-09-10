# SPDX-FileCopyrightText: 2026 Epic Games, Inc.
# SPDX-License-Identifier: MIT
import logging
import os
import random

import pytest

from lore import Lore

logger = logging.getLogger(__name__)


# Ten full mutation/push rounds over 100k files need a workload-specific guard.
@pytest.mark.timeout(21600)
@pytest.mark.slow
def test_nodeblock(new_lore_repo):
    repo: Lore = new_lore_repo()
    for i in range(10):
        logger.info("Pass " + str(i + 1) + "/10")

        first_dir = "dir_" + str(i)
        repo.make_dirs(first_dir)
        for j in range(100):
            second_dir = os.path.join(first_dir, "dir_" + str(j))
            repo.make_dirs(second_dir)
            for k in range(100):
                file_path = os.path.join(second_dir, "file_" + str(k))
                with repo.open_file(file_path, "w+b") as output_file:
                    output_file.write(os.urandom(16))

        repo.stage(scan=True)
        repo.commit("Import 10k", local=True)

    for ipass in range(10):
        logger.info("Delete and add 100k nodes pass " + str(ipass + 1) + "/100")

        # Delete 90k files
        for i in range(90000):
            i = random.randint(0, 9)
            j = random.randint(0, 99)
            k = random.randint(0, 99)
            path = "dir_" + str(i)
            path = os.path.join(path, "dir_" + str(j))
            file_path = os.path.join(path, "file_" + str(k))
            # noinspection PyBroadException
            try:
                repo.remove_file(file_path)
            except:
                pass

        # Add/modify 10k files
        for i in range(10000):
            i = random.randint(0, 9)
            j = random.randint(0, 99)
            k = random.randint(0, 99)
            path = "dir_" + str(i)
            path = os.path.join(path, "dir_" + str(j))
            file_path = os.path.join(path, "file_" + str(k))
            with repo.open_file(file_path, "w+b") as output_file:
                output_file.write(os.urandom(16))

        repo.stage(scan=True)
        repo.commit("Delete files", local=True)

        # Delete 10k files
        for i in range(10000):
            i = random.randint(0, 9)
            j = random.randint(0, 99)
            k = random.randint(0, 99)
            path = "dir_" + str(i)
            path = os.path.join(path, "dir_" + str(j))
            file_path = os.path.join(path, "file_" + str(k))
            # noinspection PyBroadException
            try:
                repo.remove_file(file_path)
            except:
                pass

        # Add/modify 95k files
        for i in range(95000):
            i = random.randint(0, 9)
            j = random.randint(0, 99)
            k = random.randint(0, 99)
            path = "dir_" + str(i)
            path = os.path.join(path, "dir_" + str(j))
            file_path = os.path.join(path, "file_" + str(k))
            with repo.open_file(file_path, "w+b") as output_file:
                output_file.write(os.urandom(16))

        repo.stage(scan=True)
        repo.commit("Add files", local=True)

        repo.push()

    clone = repo.clone()

    for i in range(10):
        first_dir = "dir_" + str(i)
        for j in range(100):
            second_dir = os.path.join(first_dir, "dir_" + str(j))
            for k in range(100):
                file_path = os.path.join(second_dir, "file_" + str(k))
                if repo.file_exists(file_path):
                    assert repo.compare_file(clone, file_path)
                else:
                    assert not clone.file_exists(file_path), (
                        "Destination file should not exist: " + file_path
                    )
