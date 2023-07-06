import mysql.connector

mydb=mysql.connector.connect(
    host='localhost',
    user='root',
    passwd='root',
    database='peks',
    auth_plugin='mysql_native_password'
)

mycursor=mydb.cursor()

#mycursor.execute("DROP TABLE PEKS")
# mycursor.execute("CREATE TABLE PEKS (\
# id INT AUTO_INCREMENT PRIMARY KEY,\
# Filesname  VARCHAR(100) NOT NULL,\
# C1 VARCHAR(1024) NOT NULL,\
# C2 VARCHAR(100) NOT NULL)")

mycursor.execute('SHOW TABLES')
for x in mycursor:
    print(x)


mycursor.execute("INSERT INTO PEKS (Filesname,C1,C2) VALUES ('test','10101010101010101','/home/karloz/Desktop/cryptoTech/database/cipher/file1')")
mycursor.execute("SELECT * FROM PEKS")
for x in mycursor:
    print(x)

mydb.commit()