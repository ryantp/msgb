# replace [$PATH] with the file path leading to the msgb directory
sroot = "[$PATH]/msgb"

priv = sroot + "/appd/config/%(user)s_privkey.txt"
pub = sroot + "/appd/config/%(user)s_pubkey.txt"