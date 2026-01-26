#!/bin/bash

echo "====================================="
echo "      schat Setup Script"
echo "====================================="
echo ""

# Check if .env already exists
if [ -f .env ]; then
    echo ".env file already exists."
    read -p "Do you want to overwrite it? (y/n): " overwrite
    if [ "$overwrite" != "y" ]; then
        echo "Setup cancelled."
        exit 0
    fi
fi

echo "Please provide the following configuration values:"
echo ""

# Database settings
read -p "Database user [postgres]: " DB_USER
DB_USER=${DB_USER:-postgres}

read -sp "Database password [postgres]: " DB_PASSWORD
echo ""
DB_PASSWORD=${DB_PASSWORD:-postgres}

read -p "Database name [schat]: " DB_NAME
DB_NAME=${DB_NAME:-schat}

read -p "Database port [5432]: " DB_PORT
DB_PORT=${DB_PORT:-5432}

# SSH settings
read -p "SSH port [2222]: " SSH_PORT
SSH_PORT=${SSH_PORT:-2222}

# Create .env file
cat > .env << EOF
# Database Configuration
DB_USER=$DB_USER
DB_PASSWORD=$DB_PASSWORD
DB_NAME=$DB_NAME
DB_PORT=$DB_PORT

# SSH Server Configuration
SSH_PORT=$SSH_PORT
EOF

echo ""
echo "Configuration saved to .env"
echo ""
echo "To start the application, run:"
echo "  docker-compose up -d"
echo ""
echo "To view logs:"
echo "  docker-compose logs -f"
echo ""
echo "To stop the application:"
echo "  docker-compose down"
echo ""
