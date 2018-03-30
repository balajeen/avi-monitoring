# avi-monitoring

Partial Avi Networks, Inc. pytest framework. <br />
Intended to demonstrate how to run provided tests against external environments.

## Setup:
* Assumes baseline VM host to act as test client. Tested against Centos 7 minimal image.
* Requires oc CLI binary to be in the PATH for running Openshift tests.
* Run . setup.sh to install/update required libraries and python packages
* Setup script sets the PYTHONPATH to ~/test/avitest but may want to do this permanently in your shell (i.e. bashrc etc)
* Update the ~/version file to match the version of your controller
* Update ~/test/avitest/avi_objects/avi_config.py to change the password field to your controller's admin password
* Update ~/test/avitest/topo_confs/example.json to match your openshift cluster and networking topology
  * controller and client vm ips and credentials
  * cloud configuration: openshift master and credentials (key files), private docker registry if applicable
  * net1 network definition for your client (e.g. PortGroup name and subnet in vcenter)

### Caveats:
Tested against internally deployed controllers so framework assume some settings that don't match your deployment. <br />
Older package versions not verified; if in doubt reinstall to the latest.

## Run:
From ~/test/avitest, execute <br />
`pytest --loglevel DEBUG --testbed topo_confs/example.json <testname> [pytest options, marks and filters] [--robot_html <desired html logfile>]`
e.g. <br />
`pytest --loglevel DEBUG --testbed topo_confs/example.json functional/mesos/test_mesos_basic.py -s -v -m "not auth and not attribute" --robot_html basic.html`

### Notes:
* The --robot_html flag enables Robot Framework-style log files; alternatively can install and use pytest-html package.
* Test class runs against internal setups with different authentication and slave node attributes, hence excluding them from the test run to only execute the generic test cases.

Additional tests and examples in the ~/test/avitest/functional/example folder (some may be out of date). <br />
Specific functional tests available by request.
