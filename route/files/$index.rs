petal::route_file!(
    spec: petal::static_dir_spec(),
    list: {
        let mut children = petal::files(&["status.json", "README.md"]);
        children.extend(petal::dir_names(&["safes", "transactions", "service-keys"]));
        children
    }
);
