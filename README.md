# The solution

In order to create a jwt-passport, I had to install the dependency and then I created the strategy in order to make it work when you login(POST), I also add a link that allows the user to logout from the account

# Fake-db

I created a JSON file that can be interpreted as a DB, then I used the bcrypt library to compare that hash with the password.

# Users

user1 : user1 (but with the bcrypt hash)
user2 : user2 (but with the bcrypt hash)