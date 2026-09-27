petal::route_file!(
    spec: petal::chain_read_spec().caps(&["bloom:store"]),
    read: |ctx: &petal::Ctx| {
        let wallet = match petal::param(ctx, "wallet") { Ok(v) => v, Err(e) => return e };
        let id = match petal::param(ctx, "id") { Ok(v) => v, Err(e) => return e };
        crate::read_plan(wallet, id)
    }
);
