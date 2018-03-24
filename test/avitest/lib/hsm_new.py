from api.Linux import Linux

def get_num_se_dp_threads(se_ip, user="admin", password="avi123"):
    cmd = "ps -efT | grep se_dp"
    vm = Linux(se_ip, user, password)
    out = vm.execute_command(cmd)
    result = []
    for line in out:
        if line.find("worker process") > 0:
            result.append(line.split(":")[-2].strip())
    return result

def get_hsm_event_counters(hsm_server_ip="10.128.1.51", user="admin", password="1!Avi123", expected_counters=[]):
    cmd = "hsm information show"
    vm = Linux(hsm_server_ip, user, password)
    out = vm.execute_command(cmd)
    hsm_stats = {}
    for line in out:
        for expected_counter in expected_counters:
            if expected_counter in line:
                hsm_stats[expected_counter] = line.split(":")[1].strip()
    return hsm_stats
