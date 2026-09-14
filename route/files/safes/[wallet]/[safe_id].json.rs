petal::route_file!(
    spec: petal::write_spec().caps(&["bloom:store","bloom:chain","bloom:vfs.read"]),
    read: |ctx: &petal::Ctx| {
        let wallet=match petal::param(ctx,"wallet"){Ok(v)=>v,Err(e)=>return e};
        let safe_id=match petal::param(ctx,"safe_id"){Ok(v)=>v,Err(e)=>return e};
        crate::read_binding(wallet,safe_id)
    },
    write: |ctx: &petal::Ctx,body:&[u8]| {
        let wallet=match petal::param(ctx,"wallet"){Ok(v)=>v,Err(e)=>return e};
        let safe_id=match petal::param(ctx,"safe_id"){Ok(v)=>v,Err(e)=>return e};
        crate::bind(wallet,safe_id,body)
    }
);
