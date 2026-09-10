petal::route_file!(
    spec: petal::signing_write_spec("safe.transaction.confirm").caps(&["bloom:store","bloom:chain","bloom:sign","bloom:http"]),
    read: |ctx:&petal::Ctx| {
        let wallet=match petal::param(ctx,"wallet"){Ok(v)=>v,Err(e)=>return e};
        let id=match petal::param(ctx,"id"){Ok(v)=>v,Err(e)=>return e};
        crate::read_transaction(wallet,id)
    },
    write: |ctx:&petal::Ctx,_body:&[u8]| {
        let wallet=match petal::param(ctx,"wallet"){Ok(v)=>v,Err(e)=>return e};
        let id=match petal::param(ctx,"id"){Ok(v)=>v,Err(e)=>return e};
        crate::confirm(ctx,wallet,id)
    }
);
