import paramiko

def ssh_command(ip, port, user, passwd, cmd):
  client = paramiko.SSHClient()
  client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
  client.connect(ip, port=port, username=user, password=passwd)
  _, stdout, stderr = client.exec_command(cmd)
  output = stdout.readlines() + stderr.readliens()
  if output:
    print('---Output---')
    for line in output:
      print(line.strip())
    client.close()

if __name__=='__main__':
  import getpass
  user = input('Enter your username: > ')
  password = getpass.getpass('Enter your passowrd: > ')
  ip = input('Enter server IP: or <CR> ') or '192.168.1.203'
  port = input('Enter PORT: or <CR> ') or 2222
  cmd = input('Enter command: or <CR>: ') or 'id'
