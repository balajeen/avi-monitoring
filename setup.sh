sudo yum -y install gcc gcc-c++ make openssl-devel libxml2-devel python-devel python-pip
sudo pip install --upgrade pip

sudo pip install boto
sudo pip install google-api-python-client
sudo pip install python-igraph
sudo pip install python-keystoneclient
sudo pip install python-novaclient
sudo pip install pysphere
sudo pip install azure
sudo pip install msrestazure

sudo pip install dnspython
sudo pip install fabric
sudo pip install paramiko
sudo pip install jsonpointer
sudo pip install jsonschema
sudo pip install oauth2client
sudo pip install protobuf
sudo pip install PyYAML
sudo pip install pytest
sudo pip install pytest-html
sudo pip install robotframework

export workspace="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
export PYTHONPATH=$workspace/test/avitest
