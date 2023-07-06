#include<iostream>
#include<fstream>
#include<string>

char DBpath[]="/home/karloz/Desktop/cryptoTech/database/db.txt";
char input[100];
char C1[1024];
char filename[100];
char cipherpath[100];
int id;



int main()
{
    std::ifstream ifs;
    ifs.open(DBpath,std::ios::in);
    while(ifs>>id)
    {
        ifs>>filename;std::cout<<filename<<std::endl;
        ifs>>C1;std::cout<<C1<<std::endl;
        ifs>>cipherpath;std::cout<<cipherpath<<std::endl;
    }
    std::cout<<std::endl;
    ifs.close();
    return 0;
}