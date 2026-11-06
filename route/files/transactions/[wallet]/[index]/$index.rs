petal::route_file!(
    spec: petal::store_dir_spec().caps(&["bloom:store"]),
    ctx_list: |ctx: &petal::Ctx| {
        let wallet = petal::wallet_param(ctx)?;
        let index = petal::param(ctx, "index")?;
        Ok(petal::dirs(crate::transaction_ids(wallet, index)?))
    }
);
