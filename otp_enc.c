#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>

// otp_enc is essentially a client that connects with the server otp_enc_d.  otp_enc sends otp_enc_d a plaintext file and a key
// and asks it to encrypt the plaintext file.  It then waits for otp_enc_d to send the encrypted message back.  When otp_enc receives
// the encrypted message, it outputs it to stdout.

// the yes string helps otp_enc when it is handshaking with otp_enc_d
char *yes = "Yes!";
// I defined a massively large and arbitrary buffer length for all of my character buffers
#define BUFFERLENGTH 100000
// We need this array in order to make sure the plaintext and key don't have illegal characters
const char alphas[] = {"ABCDEFGHIJKLMNOPQRSTUVWXYZ "};
// This is a function that professor Brewster wrote.  It spits out an error message (with perror) and exits the program
void error(const char *msg);
// sendToEncD sends the contents of buffer across whatever socket is passed in as an argument
void sendToEncD(char *buffer, int socketFD);

int main(int argc, char *argv[])
{
    // A tremendous amount of this early code is taken from professor Brewster's client.c code.  I'll comment and explain what it's doing
    // but ultimately I didn't write a lot of it.
    // socketFD is going to be the socket that we use to connect to the otp_enc_d server.
    // portNumber will be the port number that is passed in as an argument to the program
    // charsRead is used later in during send and receive attempts to make sure that data is actually being, well, sent and received
    // i and counter are both used as general-purpose counters
    int socketFD, portNumber, charsRead, i, counter;
    // We have to open up files at a certain point, so it is necessary to have the fileD pointer
    FILE *fileD;
    // Using the address struct to get our serverAddress into a form that connect and such can actually use
    struct sockaddr_in serverAddress;
    struct hostent *serverHostInfo;
    // These buffers are used to hold the key, plaintext, and (in the case of buffer) whatever 
    char keyBuffer[BUFFERLENGTH], PTbuffer[BUFFERLENGTH], buffer[BUFFERLENGTH];

    // Making sure the correct number of arguments were passed (program name, plaintext, key, port#)  Otherwise, an error is printed, and the program
    // exits
    if (argc != 4)
    {
        fprintf(stderr, "USAGE: %s hostname port\n", argv[0]);
        exit(0);
    } 
    // Set up the server address struct
    memset((char *)&serverAddress, '\0', sizeof(serverAddress)); // Clear out the address struct
    portNumber = atoi(argv[3]);                                  // Get the port number, convert to an integer from a string
    serverAddress.sin_family = AF_INET;                          // Create a network-capable socket
    serverAddress.sin_port = htons(portNumber);                  // Store the port number
    serverHostInfo = gethostbyname("localhost");                 // Convert the machine name into a special form of address
    if (serverHostInfo == NULL)
    {
        fprintf(stderr, "CLIENT: ERROR, no such host\n");
        exit(0);
    }
    memcpy((char *)&serverAddress.sin_addr.s_addr, (char *)serverHostInfo->h_addr, serverHostInfo->h_length); // Copy in the address

    // Set up the socket
    socketFD = socket(AF_INET, SOCK_STREAM, 0); // Create the socket
    if (socketFD < 0)
    {
        error("CLIENT: ERROR opening socket");
    }

    // Connect to server

    if (connect(socketFD, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0) // Connect socket to address
    {
        error("CLIENT: ERROR connecting");
    }

    // Send message to server
    // We're sending the name of the program to the server for verification purposes.  If the server is anything but otp_enc_d, the connection attempt
    // will be rejected
    memset(buffer, '\0', sizeof(buffer));
    strcpy(buffer, "otp_enc");
    sendToEncD(buffer, socketFD);

    memset(buffer, '\0', sizeof(buffer));                      // Clear out the buffer again for reuse
    charsRead = recv(socketFD, buffer, sizeof(buffer) - 1, 0); // Read data from the socket, leaving \0 at end
    if (charsRead < 0)
    {
        error("CLIENT: ERROR reading from socket");
    }
    if (strcmp(buffer, yes) != 0)
    {
        fprintf(stderr, "Error: could not contact otp_enc_d on port %d\n", argv[3]);
        exit(2);
    }

    // sending plaintext to otp_enc_d
    //  First, we pull the plaintext from the plaintext file.
    memset(PTbuffer, '\0', sizeof(PTbuffer));
    fileD = fopen(argv[1], "r");
    // I thought about using getline, but my experience with it was so bad during smallsh that I'm hesitant to try it again.  So, I just implemented a fairly standard
    // while loop fgets combo
    while (fgets(PTbuffer, BUFFERLENGTH, fileD) != NULL)
        ;
    // Closing the plaintext file
    fclose(fileD);

    counter = 0;
    i = 0;
    // We're checking to make sure that our plaintext didn't have any illegal characters. i is set to 0.  We iterate through each character in the plaintext and check to see
    // if it is in our alphas array.  If a match is found, i is set to -1 (it is incremented to 0 at the end of the loop).  This continues until a newline is found.  When
    // a newline is found, it is changed to an exclamation point (otp_enc_d uses delimiters to break up the received message into they key and plaintext) and the loop ends (and 
    // the program continues).  If a match isn't found between a character in the plaintext and the contents of the alphas array, i is incremented to the point to where the loop ends
    // and the program spits out an error about illegal characters in the plaintext (the program also exits).
    while (i < strlen(alphas) && counter < strlen(PTbuffer))
    {
        if (PTbuffer[counter] == alphas[i])
        {
            i = -1;
            counter++;
        }
        if (PTbuffer[counter] == '\n')
        {
            PTbuffer[counter] = '!';
            break;
        }
        i++;
    }
    // Illegal character found in plaintext, so program exits
    if (PTbuffer[counter] != '!')
    {
        perror("Error: Illegal character in PlainText!\n");
        exit(1);
    }
    // Calling function to send plaintext to otp_enc_d
    sendToEncD(PTbuffer, socketFD);

    // getting key from file
    memset(keyBuffer, '\0', sizeof(keyBuffer));
    fileD = fopen(argv[2], "r");
    while (fgets(keyBuffer, BUFFERLENGTH, fileD) != NULL)
        ;
    fclose(fileD);
    
    // We need to check to make sure the key is greater than or equal to the length of the plaintext (or the encryption won't work).  If the key is too short, an error message
    // is printed, and the program exits.
    if (strlen(keyBuffer) < strlen(PTbuffer))
    {
        perror("Error: Key's length is not sufficient.\n");
        exit(1);
    }
    counter = 0;
    i = 0;
    // Using the same process as above to check the key for illegal characters
    while (i < strlen(alphas) && counter < strlen(keyBuffer))
    {
        if (keyBuffer[counter] == alphas[i])
        {
            i = -1;
            counter++;
        }
        if (keyBuffer[counter] == '\n')
        {
            keyBuffer[counter] = '*';
            break;
        }
        i++;
    }
    // If the key has illegal characters, print an error and exit the program
    if (keyBuffer[counter] != '*')
    {
        perror("Error: Illegal character in key!\n");
        exit(1);
    }
    // Calling function to send key to otp_enc_d
    sendToEncD(keyBuffer, socketFD);

    // Now otp_enc needs to sit and wait to receive the ciphertext from the server.  This part was actually fairly tricky, and I had to get help from instructor Cuneo
    // for this.
    // bufferIter is used to determine if we'e actually received the entire ciphertext.  Once it equals the length of the message (this is determined by looking for
    // the exclamation point), we stop receiving and output the ciphertext to stdout
    int bufferIter = 0;
    // clearing buffer
    memset(buffer, '\0', BUFFERLENGTH);
    i = 0;
    charsRead = 0;
    // So, i is set to equal the number of characters that have been read (it obviously starts out at 0).  Everytime, we receive a chunk/batch/whatever of characters, we
    // increase i by charsRead (which is the number of characters received in a single transaction).  bufferIter is then set to equal the current length of buffer.  When
    // buffer[bufferIter -1] == '!', we've received the entire ciphertext, and we can end the loop.  But yeah, the general structure for this was mostly got from instructor
    // Cuneo (I had something sort of similar, but it was wrong and it wasn't working consistantly);
    do
    {
        charsRead = recv(socketFD, &buffer[i], BUFFERLENGTH, 0);
        i += charsRead;
        bufferIter = strlen(buffer);
    } while (buffer[bufferIter - 1] != '!');
    // Changing the '!' character to a newline per the requirements of the assignment
    buffer[bufferIter - 1] = '\n';
    // outputting the ciphertext to stdout
    write(STDOUT_FILENO, buffer, strlen(buffer));
    close(socketFD); // Close the socket
    return 0;
}

// As stated before, this function was written by professor brewster, and it is used to deal with transmission errors
void error(const char *msg)
{
    perror(msg);
    exit(1);
}

// sendToEncD sends data to otp_enc_d.  It uses a virtually identical method to the receive code that I described earlier (again, a lot of this was got from pseudocode
// written by instructor cuneo).
void sendToEncD(char *buffer, int socketFD)
{
    // When the entire message is sent, the loop ends
    int i = 0, charsRead = 0, sent = strlen(buffer), checkSend = -5;
    do
    {
        charsRead = send(socketFD, &buffer[i], sent - i, 0);
        i += charsRead;
    } while (i < sent);

    // This code is taken from professor brewster's 4.2 verified sending lecture notes.  It might be redundant (I don't think it is?), because of the code above, but
    // I'm not going to mess with any of this, because I'm just happy this program works.
    do
    {
        ioctl(socketFD, TIOCOUTQ, &checkSend); // Check the send buffer for this socket
    } while (checkSend > 0);                   // Loop forever until send buffer for this socket is empty
    if (checkSend < 0)
    {
        error("ioctl error");
    }
}