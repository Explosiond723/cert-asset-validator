import yaml
# takes 1 file yaml as input, reads it and prints a summary of the info inside.

#my_dict = {
#    "id": "placeholder",
#    "namespace": "placeholder",
#    "secret": {"name": "placeholder", "key": "placeholder"},
#    "mtls": True
#}

def validate_config(cfg: dict) -> None:
    REQ_CFG = {"id": "id_v", "namespace": "ns_v", "secret": "sec_v"}
    REQ_SECRET = {"name": "name_v", "key": "key_v"}

    if isinstance(cfg, dict):
        for item in cfg.keys:
            if isinstance(item, dict):

    return None

with open("example-cfg.yaml", "rt") as source_yaml:
    #print(source_yaml.read())
    my_dict = yaml.safe_load(source_yaml)

    print("Asset ID: ", my_dict["id"])
    print("Namespace: ", my_dict["namespace"])
    if my_dict["secret"] is None or my_dict["secret"]["key"] is None:
        print("ERROR: secret.key or secret not found in config")
    else:
        print("Secret Name & key: ", my_dict["secret"]["name"], ", ", my_dict["secret"]["key"])
    if my_dict["mtls"] is True:
        print("mTLS: yes")
    else:
        print("mTLS: no")
