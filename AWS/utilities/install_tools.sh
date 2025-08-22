#!/bin/bash

    echo "Installing tools for Linux..."

    # Install kubectl
    if ! command -v kubectl &> /dev/null; then
        echo "Installing kubectl..."
        curl -LO "https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl"
        sudo mv kubectl /usr/local/bin/kubectl
        sudo chmod +x /usr/local/bin/kubectl
    else
        echo "kubectl is already installed."
    fi

    # Install Helm
    if ! command -v helm &> /dev/null; then
        echo "Installing Helm..."
        curl -LO "https://get.helm.sh/helm-v3.7.0-linux-amd64.tar.gz"
        tar -zxvf helm-v3.7.0-linux-amd64.tar.gz
        sudo mv linux-amd64/helm /usr/local/bin/helm
        sudo chmod +x /usr/local/bin/helm
        rm -rf linux-amd64
        rm helm-v3.7.0-linux-amd64.tar.gz
    else
        echo "Helm is already installed."
    fi

    # Install Git
    if ! command -v git &> /dev/null; then
        echo "Installing Git..."
        # Check if apt-get is available
        if command -v apt-get &> /dev/null; then
            sudo apt-get update
            sudo apt-get install -y git
        # Check if yum is available
        elif command -v yum &> /dev/null; then
            sudo yum install -y git
        # Check if dnf is available
        elif command -v dnf &> /dev/null; then
            sudo dnf install -y git
        else
            echo "Unsupported package manager. Manual installation of Git required."
            exit 1
        fi
    else
        echo "Git is already installed."
    fi

    # Install AWS CLI v2
    if ! command -v aws &> /dev/null; then
        echo "Installing AWS CLI v2..."
        curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
        unzip awscliv2.zip
        sudo ./aws/install --update
        rm -rf aws
        rm awscliv2.zip
    else
        echo "AWS CLI v2 is already installed."
    fi

    # Install Python
    if ! command -v python3 &> /dev/null; then
        echo "Installing Python..."
        if command -v apt-get &> /dev/null; then
            sudo apt-get update
            sudo apt-get install -y python3 python3-pip python3-venv
        elif command -v yum &> /dev/null; then
            sudo yum install -y python3 python3-pip
        elif command -v dnf &> /dev/null; then
            sudo dnf install -y python3 python3-pip
        else
            echo "Unsupported package manager. Manual installation of Python required."
            exit 1
        fi
    else
        echo "Python is already installed."
    fi

    # Install Terraform
    if ! command -v terraform &> /dev/null; then
        echo "Installing Terraform..."
        if command -v apt-get &> /dev/null; then
            sudo apt-get update && sudo apt-get install -y gnupg software-properties-common curl
            curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
            echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
            sudo apt-get update && sudo apt-get install -y terraform
        elif command -v yum &> /dev/null; then
            sudo yum install -y yum-utils
            sudo yum-config-manager --add-repo https://rpm.releases.hashicorp.com/AmazonLinux/hashicorp.repo
            sudo yum -y install terraform
        elif command -v dnf &> /dev/null; then
            sudo dnf install -y dnf-plugins-core
            sudo dnf config-manager --add-repo https://rpm.releases.hashicorp.com/fedora/hashicorp.repo
            sudo dnf -y install terraform
        else
            echo "Unsupported package manager for Terraform."
            exit 1
        fi
    else
        echo "Terraform is already installed."
    fi

    # Install SSM Agent
    if ! command -v amazon-ssm-agent &> /dev/null; then
        echo "Installing SSM Agent..."
        sudo yum install -y https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm
        sudo systemctl start amazon-ssm-agent
        sudo systemctl enable amazon-ssm-agent
    else
        echo "SSM Agent is already installed and running."
    fi


