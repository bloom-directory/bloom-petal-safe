// Names only: the stored key is write-only and is never read back here.
petal::route_file!(
    spec: petal::store_dir_spec().caps(&["bloom:store"]),
    ctx_list: |ctx: &petal::Ctx| {
        let wallet = petal::wallet_param(ctx)?;
        let index = petal::param(ctx, "index")?;
        Ok(crate::service_key_safes(wallet, index)?
            .into_iter()
            .map(petal::writable)
            .collect())
    }
);
