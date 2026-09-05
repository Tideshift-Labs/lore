// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! Derive macro implementation for `FfiError`.
//!
//! Parses `#[ffi_code(N)]` on a struct or enum and generates an
//! `impl FfiError` that returns the given integer constant.

use proc_macro2::TokenStream;
use quote::quote;
use syn::DeriveInput;

pub fn derive_ffi_error(input: &DeriveInput) -> TokenStream {
    let name = &input.ident;

    let code = match extract_ffi_code(input) {
        Ok(lit) => lit,
        Err(err) => return err.to_compile_error(),
    };

    let identity_impl = match extract_outcome_identity(input) {
        Ok(Some((operation, attempt))) => quote! {
            fn outcome_identity(&self) -> Option<(&str, &str)> {
                Some((&self.#operation, &self.#attempt))
            }
        },
        Ok(None) => TokenStream::new(),
        Err(err) => return err.to_compile_error(),
    };

    quote! {
        // Scopes the attribute to the FFI code registry. This is a bare
        // identifier, so it resolves in the module the derive expands into
        // rather than against this crate: a `#[ffi_code(N)]` written anywhere
        // that does not declare `__ffi_code_registry_marker` fails to compile.
        // Codes share one numeric space and one process-exit-status space, so
        // they are allocated in exactly one place.
        const _: fn() = __ffi_code_registry_marker;

        impl #name {
            /// This type's FFI error code, usable in const position.
            ///
            /// Lets another declaration that must spell the same code — a
            /// `#[repr(C)]` enum discriminant, say — assert equality at compile
            /// time instead of duplicating the literal unchecked.
            pub const FFI_CODE: i32 = #code;
        }

        impl lore_error_set::FfiError for #name {
            fn ffi_code(&self) -> i32 { Self::FFI_CODE }
            #identity_impl
        }
    }
}

/// Reads an optional `#[ffi_outcome_identity(operation_field, attempt_field)]`.
///
/// Names the two fields explicitly rather than assuming a convention. An error type that has to
/// say which attempt it belongs to is rare enough that spelling the fields at the declaration is
/// cheaper than a naming rule nothing enforces, and it keeps the macro from silently binding to
/// whatever a field happens to be called after a rename.
fn extract_outcome_identity(input: &DeriveInput) -> syn::Result<Option<(syn::Ident, syn::Ident)>> {
    let mut found: Option<(syn::Ident, syn::Ident)> = None;

    for attr in &input.attrs {
        if attr.path().is_ident("ffi_outcome_identity") {
            if found.is_some() {
                // Refused rather than letting the first one quietly win. Two of these disagree
                // about which fields identify the attempt, and silently honouring one would
                // publish an identity the author did not choose.
                return Err(syn::Error::new_spanned(
                    attr,
                    "duplicate #[ffi_outcome_identity]; a type names its attempt identity once",
                ));
            }
            let fields = attr.parse_args_with(
                syn::punctuated::Punctuated::<syn::Ident, syn::Token![,]>::parse_terminated,
            )?;
            let mut fields = fields.into_iter();
            let (Some(operation), Some(attempt), None) =
                (fields.next(), fields.next(), fields.next())
            else {
                return Err(syn::Error::new_spanned(
                    attr,
                    "ffi_outcome_identity takes exactly two field names: the operation and the attempt",
                ));
            };
            // Stored rather than returned, so the loop keeps looking and a second attribute is
            // seen. Returning here would make the duplicate check above unreachable.
            found = Some((operation, attempt));
        }
    }

    Ok(found)
}

fn extract_ffi_code(input: &DeriveInput) -> syn::Result<syn::LitInt> {
    for attr in &input.attrs {
        if attr.path().is_ident("ffi_code") {
            let lit: syn::LitInt = attr.parse_args()?;
            // Validate it parses as i32.
            lit.base10_parse::<i32>().map_err(|_err| {
                syn::Error::new_spanned(&lit, "ffi_code must be an integer literal")
            })?;
            return Ok(lit);
        }
    }

    Err(syn::Error::new_spanned(
        &input.ident,
        "#[derive(FfiError)] requires #[ffi_code(N)] attribute",
    ))
}
