CREATE DATABASE IF NOT EXISTS portstraffic;
CREATE USER 'exporter'@'%' IDENTIFIED BY 'password' WITH MAX_USER_CONNECTIONS 3;
GRANT PROCESS, REPLICATION CLIENT, SELECT ON *.* TO 'exporter'@'%';
FLUSH PRIVILEGES;
USE portstraffic;
CREATE TABLE IF NOT EXISTS tcptraffic (
  TS INT UNSIGNED,
  Dest_IP VARCHAR(15),
  Dest_Port SMALLINT UNSIGNED);
