petal::route_file!(
    spec: petal::store_dir_spec().caps(&["bloom:store"]),
    ctx_list: |_ctx: &petal::Ctx| Ok(petal::dirs(crate::service_key_wallets()?))
);
