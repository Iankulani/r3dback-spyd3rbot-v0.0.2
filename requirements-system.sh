#!/bin/bash
# Spider Bot Pro - System Requirements Installer
# For Linux/Unix Systems

echo "🕸️  Spider Bot Pro - System Requirements Installer"
echo "================================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}❌ Please run as root (use sudo)${NC}"
    exit 1
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VER=$VERSION_ID
else
    echo -e "${RED}❌ Cannot detect OS${NC}"
    exit 1
fi

echo -e "${BLUE}📋 Detected OS: $OS $VER${NC}"

# Function to install on Debian/Ubuntu
install_debian() {
    echo -e "${GREEN}📦 Installing packages for Debian/Ubuntu...${NC}"
    
    apt-get update
    apt-get install -y \
        python3 \
        python3-pip \
        python3-venv \
        nmap \
        nikto \
        curl \
        wget \
        traceroute \
        dnsutils \
        net-tools \
        iptables \
        iputils-ping \
        whois \
        git \
        build-essential \
        libssl-dev \
        libffi-dev \
        python3-dev \
        chromium-browser \
        chromium-chromedriver \
        default-jre \
        jq \
        sqlite3 \
        nginx \
        supervisor
        
    # Install signal-cli
    echo -e "${GREEN}📦 Installing signal-cli...${NC}"
    wget -q https://github.com/AsamK/signal-cli/releases/download/v0.11.10/signal-cli-0.11.10.tar.gz
    tar xf signal-cli-0.11.10.tar.gz
    mv signal-cli-0.11.10 /opt/signal-cli
    ln -sf /opt/signal-cli/bin/signal-cli /usr/local/bin/signal-cli
    rm signal-cli-0.11.10.tar.gz
    
    # Install mtr
    apt-get install -y mtr-tiny
    
    echo -e "${GREEN}✅ System packages installed${NC}"
}

# Function to install on RHEL/CentOS/Fedora
install_rhel() {
    echo -e "${GREEN}📦 Installing packages for RHEL/CentOS/Fedora...${NC}"
    
    if [ "$OS" = "fedora" ]; then
        dnf install -y \
            python3 \
            python3-pip \
            nmap \
            nikto \
            curl \
            wget \
            traceroute \
            bind-utils \
            net-tools \
            iptables \
            iputils \
            whois \
            git \
            gcc \
            openssl-devel \
            python3-devel \
            chromium \
            chromedriver \
            java-11-openjdk \
            jq \
            sqlite \
            nginx \
            supervisor
    else
        yum install -y epel-release
        yum install -y \
            python3 \
            python3-pip \
            nmap \
            nikto \
            curl \
            wget \
            traceroute \
            bind-utils \
            net-tools \
            iptables \
            iputils \
            whois \
            git \
            gcc \
            openssl-devel \
            python3-devel \
            chromium \
            chromedriver \
            java-11-openjdk \
            jq \
            sqlite \
            nginx \
            supervisor
    fi
    
    # Install signal-cli
    echo -e "${GREEN}📦 Installing signal-cli...${NC}"
    wget -q https://github.com/AsamK/signal-cli/releases/download/v0.11.10/signal-cli-0.11.10.tar.gz
    tar xf signal-cli-0.11.10.tar.gz
    mv signal-cli-0.11.10 /opt/signal-cli
    ln -sf /opt/signal-cli/bin/signal-cli /usr/local/bin/signal-cli
    rm signal-cli-0.11.10.tar.gz
    
    echo -e "${GREEN}✅ System packages installed${NC}"
}

# Function to install on Arch Linux
install_arch() {
    echo -e "${GREEN}📦 Installing packages for Arch Linux...${NC}"
    
    pacman -S --noconfirm \
        python \
        python-pip \
        nmap \
        nikto \
        curl \
        wget \
        traceroute \
        dnsutils \
        net-tools \
        iptables \
        iputils \
        whois \
        git \
        base-devel \
        openssl \
        chromium \
        chromedriver \
        jre-openjdk \
        jq \
        sqlite \
        nginx \
        supervisor
        
    # Install signal-cli from AUR
    echo -e "${GREEN}📦 Installing signal-cli from AUR...${NC}"
    git clone https://aur.archlinux.org/signal-cli.git
    cd signal-cli
    makepkg -si --noconfirm
    cd ..
    rm -rf signal-cli
    
    echo -e "${GREEN}✅ System packages installed${NC}"
}

# Install based on OS
case $OS in
    ubuntu|debian)
        install_debian
        ;;
    centos|rhel|rocky|almalinux)
        install_rhel
        ;;
    fedora)
        install_rhel
        ;;
    arch)
        install_arch
        ;;
    *)
        echo -e "${RED}❌ Unsupported OS: $OS${NC}"
        exit 1
        ;;
esac

# Create Python virtual environment
echo -e "${GREEN}🐍 Setting up Python virtual environment...${NC}"
python3 -m venv /opt/spiderbot-pro/venv
source /opt/spiderbot-pro/venv/bin/activate

# Install Python requirements
echo -e "${GREEN}📦 Installing Python packages...${NC}"
pip install --upgrade pip
pip install -r requirements.txt

# Create directories
echo -e "${GREEN}📁 Creating directories...${NC}"
mkdir -p /opt/spiderbot-pro/{.spiderbot_pro,reports,scan_results,alerts,monitoring,backups,temp,scripts,nikto_results,whatsapp_session}
mkdir -p /var/log/spiderbot

# Set permissions
chmod -R 755 /opt/spiderbot-pro
chown -R $SUDO_USER:$SUDO_USER /opt/spiderbot-pro

# Create config directory
mkdir -p /etc/spiderbot
cp .spiderbot_pro/config.json /etc/spiderbot/ 2>/dev/null || true

echo -e "${GREEN}✅ System requirements installed successfully!${NC}"
echo -e "${BLUE}📁 Installation location: /opt/spiderbot-pro${NC}"
echo -e "${BLUE}🐍 Virtual environment: /opt/spiderbot-pro/venv${NC}"
echo -e "${GREEN}🚀 Run: cd /opt/spiderbot-pro && source venv/bin/activate && python spiderbot_pro.py${NC}"