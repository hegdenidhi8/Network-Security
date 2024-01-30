#include "header.h"

int main(int argc, char *argv[]){
    //Ask user to enter the password for encryption
    char passphrase[32];
    printf("Please Enter Password: ");
    gets(passphrase); 

    unsigned char key[16];
    memset(key,0,16);
    unsigned char *ciphertext=NULL;
    unsigned char** p_ciphertext=&ciphertext;
    unsigned char mac[64];
    memset(mac,0,64);
    //Send encrypted file over network
    if((argc==4) && strncmp(*(argv+2),"-d",2)==0){ 
        if (strchr(*(argv+3),':')){ //check if port number has been provided
            int sockfd = 0;
            struct sockaddr_in serv_addr; 
            
            //Read the contents of the file
            FILE *f=fopen(*(argv+1),"r");
            if (f == NULL) {
                printf("File not found\n");
            }
            int c=0,index=0;
            int fLen = getFileSize(f);
            
            char fileContents[fLen];
            memset(fileContents,0,fLen);

            while((c=fgetc(f)) && !feof(f)){
                *(fileContents+index++)=c;
            }
            fclose(f);

            if(generateKey(passphrase,key)){
                int pad=0;
                int ciphertextLen=0;
                pad=encrypt(key,passphrase,fileContents,p_ciphertext,fLen,&ciphertextLen);
                if(ciphertext){
                    //Generate SHA512 Mac for the encrypted plaintext
                    getMAC(ciphertext,ciphertextLen,mac,key,16); 
                    if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0){
                        printf("\nError while creating socket!\n");
                        return 1;
                    } 
                    memset(&serv_addr, '0', sizeof(serv_addr)); 
                    serv_addr.sin_family = AF_INET;
                    char ipParam[22];
                    memset(ipParam,0,22);
                    strncpy(ipParam,*(argv+3),21);
                    char *ipAddr;
		            char *port;
                    ipAddr = strtok(argv[3], ":"); //Get ip address from argument
                    port = strtok(NULL, ":"); //Get port number from argument
                    serv_addr.sin_port = htons(atoi(port)); 

                    if(inet_pton(AF_INET, ipAddr, &serv_addr.sin_addr)<=0)
                    {
                        printf("\n'inet_pton' Error!\n");
                        return 1;
                    } 

                    if( connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
                    {
                       printf("\nConnection Failed!\n");
                       return 1;
                    } 
                    printf("Transmitting to %s.\n",ipParam);

                    //Begin File transmission
                    char fileNameLen[20];
                    memset(fileNameLen,0,20);
                    sprintf(fileNameLen,"%zu",strlen(*(argv+1)));
                    char fileLen[20];
                    memset(fileLen,0,20);
                    sprintf(fileLen,"%d",ciphertextLen+64);
                    char padASCII[20];
                    memset(padASCII,0,20);
                    sprintf(padASCII,"%d",pad);
                    char padLen[20];
                    memset(padLen,0,20);
                    sprintf(padLen,"%zu",strlen(padASCII)); 
                    //Send File details and the encrypted content along with a delimiter '-'
                    write(sockfd,fileNameLen,strlen(fileNameLen)); 
                    write(sockfd,*(argv+1),strlen(*(argv+1))); 
                    write(sockfd,padLen,strlen(padLen)); 
                    write(sockfd,"-",1); 
                    write(sockfd,padASCII,strlen(padASCII)); 
                    write(sockfd,fileLen,strlen(fileLen));
                    write(sockfd,ciphertext,ciphertextLen);
                    write(sockfd,mac,64); 

                    printf("Successfully sent.\n");
                    free(ciphertext);
                    return 0;
                }
                else{
                    printf("Error during encryption\n");
                    return 1;
                }
            }
            else{
                printf("Error during key generation\n");
                return 1;
            }
        }
        else
        {
            printf("Invalid address!\n");
            return 1;
        }
    }
    if((argc==3) && strncmp(*(argv+2),"-l",2)==0){//Save the encrypted file locally
        char newFileName[strlen(*(argv+1)) + 3];
        memset(newFileName,0,strlen(*(argv+1))+3);
        strcpy(newFileName,*(argv+1));
        strcat(newFileName,".pur"); //Encrypted version of the file must have .pur extension
        if(file_exists(newFileName)){//Check if file with same name already exists.
            printf("Encrypted version of the file already exists\n");
            return 33;
        }else{
            //Read the contents of the file
            FILE *f=fopen(*(argv+1),"r");
            if (f == NULL) {
                printf("File not found\n");
            }
            int c=0,index=0;
            int fLen = getFileSize(f);
            
            char fileContents[fLen];
            memset(fileContents,0,fLen);

            while((c=fgetc(f)) && !feof(f)){
                *(fileContents+index++)=c;
            }
            fclose(f);

            if(generateKey(passphrase,key)) //generate key and store in the buffer named 'key
            {   
                int pad=0;
                int ciphertextLen=0;
                pad=encrypt(key,passphrase,fileContents,p_ciphertext,fLen,&ciphertextLen);  //encrypt PTXT

                if(ciphertext)
                {
                    getMAC(ciphertext,ciphertextLen,mac,key,16); 
                    char padASCII[20];
                    memset(padASCII,0,20);
                    sprintf(padASCII,"%d",pad);

                    FILE *f=fopen(newFileName,"w");
                    
                    fprintf(f,"%zu",strlen(padASCII));
                    fprintf(f,"%c",'-'); 
                    fprintf(f,"%d",pad);

                    //Write encrypted contents and mac to the output file, name ending with .pur extension
                    index=0;
                    while(index < ciphertextLen) fputc(*(ciphertext + index++),f); 

                    index=0;
                    while(index < 64) fputc(*(mac + index++),f);
                    fclose(f);

                    if(ciphertext)
                        free(ciphertext);

                    return 0;
                }
                else
                    return 1;
            }
            else
                return 1; 
        }
    }
    else{//Invalid arguments
        fprintf(stderr, "usage %s <input-file> [-d <IP-addr:port>] [-l]\n", argv[0]);
        return 1;
    }
}