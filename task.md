# Task
Make an SSH chat application in go that support user registration and admins.

## features
- Seamless SSH connection handling
- User registration and authentication via ssh keys or passwords
- Admin roles with elevated privileges
 Commands have a few intuitive keywords if you forget the original name. Tab completion is also supported.
- PostgreSQL database integration for storing user data and chat history
- Real-time chat functionality
- rooms support and broadcast messages and private messages
- Banning users for specific duration, kicking users (from 2 minutes to 24 hours) and muting on specific duration. Duration is set with colon separated format.
- Logging of all chat messages and user actions for audit purposes (pm logging is disabled by default but can be enabled by admin if he is a badass)
- bell character on new message settings per user
- User settings are stored in the database
- @me command for emotes, with support of putting it in the middle of the message
- nicknames and status messages
- @mentions support with /mentiones command to list all mentions

## Recommendations
- crypto/ssh and gorm is already added to the go.mod file
- Make the code well structured and modular for easy maintenance and scalability.
- Screenreader support is priority! Don't make =======()()()()() etc for UI elements.
- If it is possible by the ssh protocol, make keyboard shortcuts for needed actions like switching rooms, sending private messages, etc. They will preenter a special command in the input line when pressed.
- when entered anonymously, the user needs to register. It asks for a username and (password / key). It detects if it's a key or password by the input format. The key input must be multiline I guess and it must stop reading when the user inputs a specific line like "END KEY" or something.



## docker
The app must be dockerized using docker compose. The setup.sh script must ask for needed environment variables and create a .env file for docker compose to use. The database must be in a separate container. The database container must have a volume for data persistence.