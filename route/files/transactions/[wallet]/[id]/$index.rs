petal::route_file!(
    spec: petal::static_dir_spec(),
    list: petal::files(&["draft.json","confirm.json","execute.json","status.json"])
);
