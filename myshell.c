#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>

void myPrint(char *msg, int batch)
{
	if (batch){
		write(STDOUT_FILENO, msg, strlen(msg));
	}else{
		return;
	}
}

void myError()
{
	char error_message[30] = "An error has occurred\n";
	write(STDOUT_FILENO, error_message, strlen(error_message));
}

int count_args(char *inputted_line, int flag) {
	int count = 0;
	int inside_token = 0; 

	for (const char *ptr = inputted_line; *ptr != '\0'; ptr++) {
		if ((!flag && !isspace(*ptr)) || (flag && *ptr != ';')) {
		    if (!inside_token) {
			if(*ptr != '\n'){
				count++;
				inside_token = 1;
			}
		    }
		} else {
		    inside_token = 0;
		}
	}
    return count;
}

void add_other_args(char** args)
{
	int i = 1;
	char* token;
	while ((token = strtok(NULL, " 		")) != NULL){
		if (strcmp(token, "\n")){ 
			args[i] = token;
			i++;
		}
	}
	args[i-1][strcspn(args[i-1], "\n")] = '\0';
	args[i] = NULL;
}

char* copy_str(char* initial_str)
{
	int str_len = strlen(initial_str) + 1;
        char* copy_str = (char*)malloc(str_len);
	if (copy_str == NULL) {
		perror("malloc failed");
		exit(1);
	    }
	strcpy(copy_str, initial_str);
	return copy_str;
}
int check_builtin(char* input)
{
	if (strcmp(input, "cd\n") == 0){
		return 1;
	} else if (strcmp(input, "cd") == 0){
		return 11;
	}else if (strcmp(input,"exit\n") == 0 || strcmp(input,"exit") == 0){
       		return 2;
	} else if (strcmp(input,"pwd\n") == 0){
		return 3;
	} else if (strcmp(input,"pwd") == 0){
		return 33;
	}else{
		return -1;
	}
}

int check_redir(char* input){
	
	int flag = 0;
	int flag2 = 0;	
	char* ptr = input;

	if (*ptr == '>'){
		return flag;
	}

	for(; *ptr != '\0'; ptr++){	
		if ((*ptr != ' ') && (*ptr != '	') && (*ptr != '+') && (*ptr != '>')){
			flag2 = 1;
		}
		if (*ptr == '>'){
			if (flag == 0){
				if(*(ptr+1) == '+'){
					flag = 2;
				}else{
					flag = 1;
				}
			}else if ((flag == 1) || (flag == 2)){
				flag = -1;
			}
		}		
	}
	
	if ((flag2 == 0) && (flag)){
		flag = -1;
	}
	return flag;
}

int execute_bi(int input)
{
	if (input == 1){
		char *home = getenv("HOME");
		if (home != NULL) {
			chdir(home);
			return 0;
		}else{
			myPrint("couldn't get home variable", 1);
			return -1;
		}
	}else if(input == 11){
		char* after_cd = strtok(NULL, " 	");
		char* scnd_after_cd = strtok(NULL, " 	");
		if ((strcmp(after_cd, "\n")) == 0){
			char *home = getenv("HOME");
		       	chdir(home);
			return 0;
		}else if ((scnd_after_cd == NULL) || strcmp(scnd_after_cd, "\n") == 0){
		       	after_cd[strcspn(after_cd, "\n")] = '\0';
			int check = chdir(after_cd);
			if (check == -1){
				myError();
				return -1;
			}
			return 0;
			
		}else{
			myError();
			return -1;
		}

	}else if (input == 2){
		char* after_exit = strtok(NULL, " 	");
		if (after_exit == NULL || strcmp(after_exit, "\n") == 0){
			exit(0);
		}else{
			myError();
			return -1;
		}
	}else if (input == 3 || input == 33){	
		if (input == 33){
			char* after_pwd = strtok(NULL, " 	");
			if (after_pwd != NULL && strcmp(after_pwd, "\n") != 0){
				myError();
				return -1;
			}
		}
		char buff[4096];
		char* cur_dir = getcwd(buff, 4096);
		myPrint(cur_dir, 1);
		myPrint("\n", 1);
		return 0;

	}else{
		return 1;//unexpected input
	}

}

void print_trailing_chars(FILE* file)
{
	int s;
	while ((s = fgetc(file)) != '\n'){
		putchar(s);
		fflush(stdout);
	}
	putchar(s);
	fflush(stdout);
}

int check_length(char* input)
{
	int i = 0;
	int flag = 0;
	while(i < 514){
		if (input[i] == '\n'){
			flag = 1;
			break;
		}
		i++;
	}
	if(!flag){
		return -1;
	}

	return 0;
}

int print_single_command(char* pinput, FILE* inp_strm)
{
        pid_t pid;
        int status;
	char* input;

	int arg_num = count_args(pinput, 0) + 1;
	
	char *token = strtok(pinput, "		 ");
        if ((token != NULL) && (strcmp(token, "\n") != 0)) {
		input = token;
	}else{
		return 4;
	}

	int bi_command = check_builtin(input); 
	if (bi_command != -1){
		int check = execute_bi(bi_command); 
		if (check != 1){
			return 2;
		}
	}
	
	char* exec_args[arg_num];
	exec_args[0] = input;
	add_other_args(exec_args);

	pid = fork();

	if (pid < 0){
		perror("fork fail");
		exit(2);
	} else if (pid == 0){	
		if (execvp(input, exec_args) == -1){
			//myPrint("hey", 1);
			myError();
			exit(1);	
		}//fork, before or after validity check?
	}else {
		if (waitpid(pid, &status, 0) == -1) {
		    perror("waitpid fail");
		    exit(1);
		}else{
			return 3;
		}
        }
	return -1;
}

int process_redir(char* input, int redir, FILE* inp_strm)
{
	char* output_file = NULL;
	char* command;	

	if (redir == 1){
		command = strtok(input, ">");
	}else{
		command = strtok(input, ">+");
	}


	char* file_adayi = strtok(NULL, "+\n 	");

	char* token = strtok(NULL, "\n	 ");  
	
	if ((file_adayi == NULL) || (token != NULL)){
		return -1;
	}else{
		output_file = file_adayi;
	}
	
	
	int exist = access(output_file, F_OK);
	if (redir == 1){
		if (exist == 0) {	
			return -1;
		}
	}else{
		if (exist == -1){
			redir = 1;
		}
	}

	int leng = strlen(command);
	char* passed_arg = malloc((leng + 2) * sizeof(char));
	if (!passed_arg) {
		perror("Memory allocation failed");
		exit(1);
	}
	strncpy(passed_arg, command, leng);
	passed_arg[leng] = '\n';
	passed_arg[leng+1] = '\0';

	char* first_com = strtok(command, " 	");
	int bi_command = check_builtin(first_com);
        if (bi_command != -1){
		free(passed_arg);
                return -1;
        }

	int fd = open(output_file, O_RDWR | O_CREAT, 0644);
	if (fd == -1) {
		free(passed_arg);
		return -1;
	}

	if (redir == 1){

		int temp_fd_out = dup(STDOUT_FILENO);

		if (dup2(fd, STDOUT_FILENO) == -1) {
			perror("dup2");
			exit(1);
		}

		close(fd);

		int ret_val = print_single_command(passed_arg, inp_strm);
		if (ret_val == -1){
			return -1;
		}
		if (dup2(temp_fd_out, STDOUT_FILENO) == -1) {
			perror("dup2");
			exit(1);
		}
		close(temp_fd_out);
	} else{
		char buff[4096];
   		ssize_t bytes_read;
		ssize_t bytes_written;
		int temp_fd_out = dup(STDOUT_FILENO);

		int fd_temp_write = open("buff_file", O_WRONLY | O_CREAT | O_TRUNC | O_APPEND, 0644);
		while ((bytes_read = read(fd, buff, 4096)) > 0) {
			if (bytes_read < 0) {
			    perror("read faild");
			    close(fd);
			    exit(1);
			}
		        bytes_written = write(fd_temp_write, buff, bytes_read);
			if (bytes_written < 0) {
			    perror("write faild");
			    close(fd_temp_write);
			    exit(1);
			}
		}
		close (fd_temp_write);
		close(fd);

		int trunc_output_fd = open(output_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	
		dup2(trunc_output_fd, STDOUT_FILENO);
        	close(trunc_output_fd);

		int ret_val = print_single_command(passed_arg, inp_strm);
		if (ret_val == -1){
			return -1;
		}
		
		int fd_temp_read = open("buff_file", O_RDONLY, 0644);
		int fd_output_write = open(output_file, O_WRONLY | O_APPEND, 0644);
		if (fd_temp_read < 0 || fd_output_write < 0) {
		    perror("open or write failed");
		    exit(1);
		}
		while ((bytes_read = read(fd_temp_read, buff, 4096)) > 0) {
                        if (bytes_read < 0) {
                            perror("read");
                            close(fd);
                            exit(1);
                        }
                        bytes_written = write(fd_output_write, buff, bytes_read);
                }

		close(fd_temp_read);
		close(fd_output_write);

		remove("buff_file");

		if (dup2(temp_fd_out, STDOUT_FILENO) == -1) {
                        perror("dup2 failed");
                        exit(1);
                }
                close(temp_fd_out);
	}
	free(passed_arg);

	return 1;
}

int main(int argc, char *argv[]) 
{
    FILE* inp_strm = stdin;
    char cmd_buff[514];
    char *pinput;
    int batch_mode = 0;

    if (argc > 2){
	    myError();
	    exit(1);
    }

    if (argc == 2){
    	 inp_strm = fopen(argv[1], "r");
	 batch_mode = 1;
	 if (inp_strm == NULL) {
	    myError();
            exit(1);
        }
    }

    while (1) {
	myPrint("myshell> ", 1 ^ batch_mode);
        pinput = fgets(cmd_buff, sizeof(cmd_buff), inp_strm);
	if (pinput == NULL) {
            if (inp_strm != stdin) {
                fclose(inp_strm); 
            }
            exit(0);
        }

	int not_empty_line = 0;
	
	for(char* ptr = cmd_buff; *ptr != '\0'; ptr++){
		if ((*ptr != ' ') && (*ptr != '	')){
			if (*ptr != '\n'){
				not_empty_line = 1;
				break;	
			}
		}
	}

	if (!not_empty_line){
		continue;
	}

	if (check_length(cmd_buff) == -1){
        	myPrint(cmd_buff, 1);	
	       	print_trailing_chars(inp_strm);//for long commands
	        myError();
	       	continue;
	}
        
	myPrint(cmd_buff, batch_mode);	
	
	int arg_num = count_args(pinput, 1);
	char* outer_args[arg_num];

	char* token = strtok(pinput, ";");
	
	
	int i =0;
	
	while (token != NULL) {
		int token_len = strlen(token);
		char* passed_arg = malloc((token_len + 2) * sizeof(char)); 
		if (!passed_arg) {
			perror("Memory allocation failed");
			exit(1);
		}

		strncpy(passed_arg, token, token_len);  
		token = strtok(NULL, ";");          
		
		if((i+1 != arg_num) || ((i+1 == arg_num) && (token != NULL)) ){
			passed_arg[token_len] = '\n';          
		}else{
			passed_arg[token_len] = '\0';          
		}

		passed_arg[token_len + 1] = '\0';     

		outer_args[i] = passed_arg;          
		i++;

	}	

	i = 0;
	int redir;
	int return_val;
	while (i < arg_num){
		redir = check_redir(outer_args[i]);
		if((redir == 1) || (redir == 2)){
			int val = process_redir(outer_args[i], redir, inp_strm);
			if(val == -1){
				myError();
			}

		}else if(redir == -1){
			myError();
		}else{
			return_val = print_single_command(outer_args[i], inp_strm);
			if (return_val == -1){
				myError();
			}
		}
		free(outer_args[i]);
		i++;
	}
    }
}
