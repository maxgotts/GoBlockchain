## Instructions
   
# Users
Create a user by name /createuser/{name}
Create a number of users: /createusers/{iterations}
List users: /users
List a user by address or name (if there are duplicates in name, then the first instance created is used): /users/{user} OR /user/{user}
    
Add a number of transactions between created users to the unordered pile: /addrandomblock
Add a number of transactions between random names to the unordered pile: /addfullyrandomblock
Add a transaction to the unordered pile: /addtx/{sender}/{reciever}/{amount}/{memo}  OR  /addtransaction/{sender}/{reciever}/{amount}/{memo}
    
Mine a block from the unordered pile: /mine
See the blockchain: /blockchain
    
Change the difficulty of the blockchain: /difficulty/{difficulty}
Change the maximum number of transactions in a block: /size/{size}
Restart the chain: /restart
Restart with certain parameters: /restart/{name}/{coin}/{difficulty}/{size}