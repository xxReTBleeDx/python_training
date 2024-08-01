import paramiko

def ssh_command(ip, port, user, passwd, cmd):
  client = paramiko.SSHClient()
  client.connect(ip, port, username=user, password=passwd)
  _, stdout, stderr = client.exec_command(cmd)
  output = stdout.readlines() + stderr.readlines()
  if output:
    print('--Output--')
    for line in output:
      print(line.strip())
    client.close()

if __name__=='__main__':
  import getpass
  user = input('Username: ')
  password = getpass.getpass()
  ip = input('Enter server IP: ') or 2222
  ssh_command(ip, port,  user, password, cmd)
  
