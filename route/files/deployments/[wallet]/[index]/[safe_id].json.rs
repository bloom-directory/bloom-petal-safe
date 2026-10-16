petal::route_file!(
    spec: petal::write_spec().caps(&["bloom:store","bloom:chain","bloom:vfs.read","bloom:tx.outbox"]),
    read: |ctx: &petal::Ctx| {
        let wallet=match petal::wallet_param(ctx){Ok(v)=>v,Err(e)=>return e};
        let index=match petal::param(ctx,"index"){Ok(v)=>v,Err(e)=>return e};
        let safe_id=match petal::param(ctx,"safe_id"){Ok(v)=>v,Err(e)=>return e};
        crate::read_deployment(wallet,index,safe_id)
    },
    write: |ctx: &petal::Ctx,body:&[u8]| {
        let wallet=match petal::wallet_param(ctx){Ok(v)=>v,Err(e)=>return e};
        let index=match petal::param(ctx,"index"){Ok(v)=>v,Err(e)=>return e};
        let safe_id=match petal::param(ctx,"safe_id"){Ok(v)=>v,Err(e)=>return e};
        crate::deploy(wallet,index,safe_id,body)
    }
);
