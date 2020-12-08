from flask import Flask, request, jsonify
import ast
from Encryption import *
from data_access import *


# Generate the Server RSA Keys
generate_rsa_keys(2048,'server_private.pem','server_public.pem')

# Generate the IV for AES and respective key
iv_key()
aes_key_iv = read_iv_key()
aes_key = aes_key_iv[:32]
aes_iv = aes_key_iv[32:]

app = Flask(__name__)

def process_vote(voteJSON):
    # print(voteJSON["SessionID"])
    # print(voteJSON["Votes"]["President"])
    # print(voteJSON["Votes"]["NJ State Senator"])

    # Check session eligibility: check that session id's 
        # user matches up with SSN and DOB in e-sig
    sessions_jda = JsonDataAccess("sessions.json")
    userPair = sessions_jda.search(voteJSON["SessionID"])
    
    if userPair is None:
        return -1

    username = userPair["username"]

    # Now that we have the username of the voter,
        # we match their SSN & DOB
    users_jda = JsonDataAccess("users.json")
    userInfo = users_jda.search(username)
    print(userInfo)
    

    votes_jda = JsonDataAccess("votes.json")
    if votes_jda.search("President") is None:
        votes_jda.insert([], "President")
        votes_jda.insert([], "NJ State Senator")


@app.route('/vote', methods = ['POST'])
def receive_vote():
    data = request.get_json(force=True)
    data = ast.literal_eval(data)
    
    payload = data["payload"]
    vote_dict = rsa_decryption(payload, 'server')
    vote_dict = ast.literal_eval(vote_dict)



    procExit = process_vote(vote_dict)


    # needs to decrypt payload and e_sig


    # check that session id's user matches up with SSN and DOB in e-sig
    incorrect_e_sig = False
    if (procExit == -1):
        incorrect_e_sig = True
    # Make sure that user can vote
    unable_to_vote = False
    if (procExit == -2):
        unable_to_vote = True
    # Vote

    # If error return 401 for incorrect e_sig, 402 for inability to vote (and descriptive message)
    if incorrect_e_sig:
        return "Invalid E-Signature: DOB, SSN and/or session ID does not match user's info", 401
    if unable_to_vote:
        return "User has either already voted or is unable to vote.", 402
    # otherwise return 200 status code and a success message
    return "Vote has been placed, thank you.", 200

if __name__ == "__main__":
    app.debug = True
    app.run()