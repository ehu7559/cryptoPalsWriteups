#Break SRP with a zero key

#imports
from s5c36 import generate_test_params, hash_sha256, server_init, server_send_B,server_side_compute, client_side_compute, client_send_salted_HMAC,server_verdict

def client_send_0_as_A(init_params):
    return (init_params + (0, 0), 0)

def client_gen_zerokey_HMAC(salt):
    K = hash_sha256(bytes()) #Server computes A=0 which is encoded as empty here.
    return client_send_salted_HMAC((K, salt))

#Run SRP protocol with 0-key vulnerability
def SRP_ZeroKey(test_params, test_constants):
    _, test_b = test_constants #The value of a in this test doesn't matter.

    #Pass different parameters to client vs server.
    N, g, k, I, P = test_params
    client_params = (N, g, k, I, "Unknown Password") #Client gets no password.

    print("Server Initializing...", end="")
    server_initialized           = server_init(test_params)
    print("Done")

    print("Client Initializing Without Password, Sending A=0...", end="")
    client_initialized, client_A = client_send_0_as_A(client_params)
    print("Done")

    print("Server Sending B... ", end="")
    server_post_B, server_B      = server_send_B(server_initialized, test_b)
    print("Done")
    
    #TODO: Remove this, simply grab the salt.
    print("Client Side Computing... ", end="")
    client_side_computation      = client_side_compute(client_initialized, server_B)
    print("Done")

    print("Server Side Computing... ", end="")
    server_side_computation      = server_side_compute(server_post_B, client_A)
    print("Done")

    print("Client Sending modified K HMAC... ", end="")
    
    #Modify K
    client_K, client_salt        = client_side_computation
    client_send_HMAC =  client_gen_zerokey_HMAC(client_salt)
    print("Done")
    
    print("Server Verifying HMAC... ", end="")
    server_get_verdict           = server_verdict(server_side_computation,client_send_HMAC)
    print("Done")

    print(f"Validated: " + str(server_get_verdict))

if __name__ == "__main__":
    run_params, run_constants = generate_test_params()
    SRP_ZeroKey(run_params, run_constants)