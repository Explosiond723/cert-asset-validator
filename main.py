import yaml
# takes 1 file yaml as input, reads it and prints a summary of the info inside.

#my_dict = {
#    "id": "placeholder",
#    "namespace": "placeholder",
#    "secret": {"name": "placeholder", "key": "placeholder"},
#    "mtls": True
#}

def validate_config(cfg: dict) -> None:
    REQ_CFG = ("id", "namespace", "secret")
    REQ_SECRET = ("name", "key")
    
    if cfg is None or not isinstance(cfg, dict):
#        print("ERROR: config file not found or not in the correct format")
        raise ValueError(f"ERROR: config file not found or not in the correct format") 
    else:
        for item in REQ_CFG:
            if item not in cfg:
#                print("ERROR: Missing required field: ", item)
                raise ValueError(f"ERROR: Missing required field: {item}")
            
            #check on keys: secret if is a dict
            if item == "secret" and not isinstance(cfg[item], dict):
#                print ("ERROR: Field 'secret' must be a dictionary")
                raise ValueError(f"ERROR: Field 'secret' must be a dictionary")
            else:
                for s_item in REQ_SECRET:
                    if s_item not in cfg[item]:
#                        print("ERROR: Missing required field: secret.", s_item)
                        raise ValueError(f"ERROR: Missing required field: secret.{s_item}")

    #if isinstance(cfg, dict):
    #    for item in cfg.keys:
    #        if isinstance(item, dict):

    return None

with open("example-cfg.yaml", "rt") as source_yaml:
    #print(source_yaml.read())
    my_dict = yaml.safe_load(source_yaml)
    validate_config(my_dict)

    print("Asset ID: ", my_dict["id"])
    print("Namespace: ", my_dict["namespace"])
#    if not isinstance(my_dict["secret"], dict) or my_dict["secret"] is None:
#        print("ERROR: secret.key or secret not found in config")
#    else:
    print("Secret Name & key: ", my_dict["secret"]["name"], ", ", my_dict["secret"]["key"])

    print("MTLS: ", my_dict.get("mtls", "Unknown") )
