petal::route_file!(
    spec: petal::write_spec().caps(&["bloom:store","bloom:chain","bloom:http","bloom:tx.outbox"]),
    read: |ctx:&petal::Ctx| {
        let wallet=match petal::param(ctx,"wallet"){Ok(v)=>v,Err(e)=>return e};
        let id=match petal::param(ctx,"id"){Ok(v)=>v,Err(e)=>return e};
        crate::read_transaction(wallet,id)
    },
    write: |ctx:&petal::Ctx,body:&[u8]| {
        let wallet=match petal::param(ctx,"wallet"){Ok(v)=>v,Err(e)=>return e};
        let id=match petal::param(ctx,"id"){Ok(v)=>v,Err(e)=>return e};
        crate::execute(wallet,id,body)
    }
);
