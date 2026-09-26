petal::route_file!(
    spec: petal::store_dir_spec().caps(&["bloom:store"]),
    ctx_list: |ctx: &petal::Ctx| {
        let wallet = petal::param(ctx, "wallet")?;
        Ok(crate::bound_safes(wallet)?
            .into_iter()
            .map(|safe_id| petal::writable(format!("{safe_id}.json")))
            .collect())
    }
);
