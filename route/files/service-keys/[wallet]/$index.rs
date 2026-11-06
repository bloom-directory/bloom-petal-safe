// Bloom supplies the live wallet and account directory inventory from its
// own authenticated projection; this Petal does not enumerate accounts itself.
petal::route_file!(spec: petal::static_dir_spec(), list: Vec::new());
