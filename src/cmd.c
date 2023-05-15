// SPDX-License-Identifier: BSD-3-Clause

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#include "cmd.h"
#include "utils.h"

#define READ		0
#define WRITE		1

#define min(a, b) (((a) < (b)) ? (a) : (b))


/**
 * Internal change-directory command.
 */
static bool shell_cd(word_t *dir)
{
	bool oldpwd = false;
	char *directory;

	if (!dir) {
		/* BONUS 1 - 'cd' - changes dir to $HOME, if defined */
		directory = getenv("HOME");
		if (!directory)
			return 1;
	} else {
		directory = get_word(dir);
		if (!directory[0]) {
			free(directory);
			return 1;
		}

		/* BONUS 2 - 'cd -' - changes dir to $OLDPWD, if defined */
		if (!strcmp(directory, "-")) {
			oldpwd = true;
			free(directory);
			directory = getenv("OLDPWD");
			if (!directory)
				return 1;
		}
	}

	/* chdir() call to change the current directory */
	if (chdir(directory) != 0) {
		free(directory);
		perror("cd");
		return 1;
	}

	/* Memory deallocate */
	if (dir && !oldpwd)
		free(directory);

	return 0;
}


/**
 * Internal exit/quit command.
 */
static int shell_exit(void)
{
	/* Close all open file descriptors */
	int fdmin = min(STDIN_FILENO, min(STDOUT_FILENO, STDERR_FILENO));
	int fdmax = (int)sysconf(_SC_OPEN_MAX);

	for (int i = fdmin; i < fdmax; i++)
		close(i);

	return SHELL_EXIT;
}


/**
 * Erases the contents of a file.
 */
static void erase_file(char *file)
{
	int fd = open(file, O_WRONLY | O_CREAT | O_TRUNC, 0666);

	close(fd);
}


/**
 * @brief Redirects the given stream to a file.
 *
 * @param stream stdin / stdout/ stderr
 * @param file the file to which the redirection is done
 * @param flags the file opening flags
 * @return 0 - success / 1 - error
 */
static int redirect_stream(int stream, char *file, int flags)
{
	if (!file)
		return 0;

	// Open the file using the given flags
	int file_fd = open(file, flags, 0666);

	if (file_fd == -1) {
		perror("open");
		return 1;
	}

	// Redirect the current stream to the file
	if (dup2(file_fd, stream) == -1) {
		close(file_fd);
		perror("dup2");
		return 1;
	}

	// Close the file descriptor
	close(file_fd);

	return 0;
}


/**
 * @brief Computes the file opening flags based on the @io_flags param.
 * @param out_flags the computed out flags
 * @param err_flags the computed err flags
 */
static void compute_flags(int io_flags, char *output_file, char *error_file,
						  int *out_flags, int *err_flags)
{
	*out_flags = O_TRUNC;
	*err_flags = O_TRUNC;
	if (output_file && error_file && !strcmp(output_file, error_file)) {
		/* '&>' - redirect both err and out to the same file */
		erase_file(output_file);
		*out_flags = O_APPEND;
		*err_flags = O_APPEND;
	}

	if (io_flags == (IO_OUT_APPEND | IO_ERR_APPEND)) {
		*out_flags = O_APPEND;
		*err_flags = O_APPEND;
	} else if (io_flags == IO_OUT_APPEND) {
		*out_flags = O_APPEND;
	} else if (io_flags == IO_ERR_APPEND) {
		*err_flags = O_APPEND;
	}
}


/**
 * Frees the command and its args, allocated by get_word().
 */
static void free_command_and_args(char *command, int no_args, char **args)
{
	free(command);
	for (int i = 0; i < no_args; i++)
		free(args[i]);
}


/**
 * Frees the words (strings) allocated by get_word().
 */
static void free_strings(int num, ...)
{
	va_list valist;

	va_start(valist, num);
	for (int i = 0; i < num; i++)
		free(va_arg(valist, char*));
	va_end(valist);
}


/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */
static int parse_simple(simple_command_t *s, int level, command_t *father)
{
	int status;

	int no_args;
	char *command = get_word(s->verb);
	char **args = get_argv(s, &no_args);

	char *input_file = get_word(s->in);
	char *output_file = get_word(s->out);
	char *error_file = get_word(s->err);

	/* Compute the proper flags for out & err files */
	int out_flags, err_flags;

	compute_flags(s->io_flags, output_file, error_file,
				  &out_flags, &err_flags);


	/* If builtin command, execute the command. */
	if (!strcmp(command, "exit") || !strcmp(command, "quit")) {
		free_command_and_args(command, no_args, args);
		free_strings(4, input_file, output_file, error_file, args);

		return shell_exit();
	} else if (!strcmp(command, "cd")) {
		// Save the original stdout & stderr file descriptors
		int original_stdout = dup(STDOUT_FILENO);
		int original_stderr = dup(STDERR_FILENO);

		/* Redirect out & err streams if the case */
		int tmp;

		tmp = redirect_stream(STDOUT_FILENO, output_file, O_WRONLY | O_CREAT | out_flags);
		if (tmp == 1)
			return 1;
		tmp = redirect_stream(STDERR_FILENO, error_file, O_WRONLY | O_CREAT | err_flags);
		if (tmp == 1)
			return 1;

		/* Execute built-in cd */
		int status = shell_cd(s->params);

		/* Redirect out & err back to the std */
		if (dup2(original_stdout, STDOUT_FILENO) == -1) {
			perror("dup2");
			return 1;
		}
		if (dup2(original_stderr, STDERR_FILENO) == -1) {
			perror("dup2");
			return 1;
		}

		close(original_stderr);
		close(original_stdout);

		/* Free the memory */
		free_command_and_args(command, no_args, args);
		free_strings(4, input_file, output_file, error_file, args);

		return status;
	}


	/* If variable assignment, execute the assignment and return
	 * the exit status.
	 */
	if (s->verb->next_part != NULL) {
		const char *name = s->verb->string;
		char *value;

		if (!strcmp(s->verb->next_part->string, "=")) {
			if (s->verb->next_part->next_part == NULL) {
				free_command_and_args(command, no_args, args);
				free_strings(4, input_file, output_file, error_file, args);
				return 1;
			}

			value = get_word(s->verb->next_part->next_part);
		} else {
			free_command_and_args(command, no_args, args);
			free_strings(4, input_file, output_file, error_file, args);
			return 1;
		}

		free_command_and_args(command, no_args, args);
		free_strings(4, input_file, output_file, error_file, args);

		int tmp = setenv(name, value, 1);

		if (value)
			free(value);
		return tmp;
	}


	/* If external command:
	 *   1. Fork new process
	 *     2c. Perform redirections in child
	 *     3c. Load executable in child
	 *   2. Wait for child
	 *   3. Return exit status
	 */
	pid_t pid = fork();

	if (pid == -1) {
		// Error occurred while forking
		perror("fork");
		free_command_and_args(command, no_args, args);
		free_strings(4, input_file, output_file, error_file, args);
		return 1;
	} else if (pid == 0) {
		// Child process

		/* STDIN, STDOUT, STDERR redirection */
		int tmp;

		tmp = redirect_stream(STDIN_FILENO, input_file, O_RDONLY);
		if (tmp == 1)
			exit(EXIT_FAILURE);
		tmp = redirect_stream(STDOUT_FILENO, output_file, O_WRONLY | O_CREAT | out_flags);
		if (tmp == 1)
			exit(EXIT_FAILURE);
		tmp = redirect_stream(STDERR_FILENO, error_file, O_WRONLY | O_CREAT | err_flags);
		if (tmp == 1)
			exit(EXIT_FAILURE);

		/* Load executable in child */
		int ret = execvp(command, args);

		if (ret == -1)
			fprintf(stderr, "Execution failed for '%s'\n", command);
		exit(EXIT_FAILURE);
	} else {
		// Parent process

		free_command_and_args(command, no_args, args);
		free_strings(4, input_file, output_file, error_file, args);

		if (waitpid(pid, &status, 0) == -1) {
			// Error occurred while waiting for the child process
			perror("waitpid");
			return 1;
		}

		if (WIFEXITED(status))
			return WEXITSTATUS(status);
	}

	return 0;
}

/**
 * Process two commands in parallel, by creating two children.
 */
static bool run_in_parallel(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	int status;
	pid_t pid1, pid2;

	// Fork a child process - cmd1
	pid1 = fork();

	if (pid1 == -1) {
		perror("fork");
		return 1;
	} else if (pid1 == 0) {
		// Child process - execute cmd1
		exit(parse_command(cmd1, level + 1, father));
	}

	// Fork a child process - cmd2
	pid2 = fork();

	if (pid2 == -1) {
		perror("fork");
		return 1;
	} else if (pid2 == 0) {
		// Child process - execute cmd2
		exit(parse_command(cmd2, level + 1, father));
	}

	// Wait for both child processes to finish
	waitpid(pid1, &status, 0);
	waitpid(pid2, &status, 0);

	// Return true or false based on the exit status of cmd2
	if (WIFEXITED(status))
		return WEXITSTATUS(status);

	return 0;
}

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2).
 */
static bool run_on_pipe(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	/* Redirect the output of cmd1 to the input of cmd2. */
	int status;
	int pipefd[2];
	pid_t pid1, pid2;

	// Create a pipe
	if (pipe(pipefd) == -1) {
		perror("pipe");
		return 1;
	}

	// Fork a child process - cmd1
	pid1 = fork();

	if (pid1 == -1) {
		perror("fork");
		return 1;
	} else if (pid1 == 0) {
		// Child process

		// Duplicate stdout to the write end of the pipe
		if (dup2(pipefd[1], STDOUT_FILENO) == -1) {
			perror("dup2");
			exit(EXIT_FAILURE);
		}

		// Close unused file descriptors
		close(pipefd[0]);
		close(pipefd[1]);

		// Execute cmd1
		exit(parse_command(cmd1, level + 1, father));
	}

	// Fork a child process - cmd2
	pid2 = fork();

	if (pid2 == -1) {
		perror("fork");
		return 1;
	} else if (pid2 == 0) {
		// Child process

		// Duplicate stdout to the write end of the pipe
		if (dup2(pipefd[0], STDIN_FILENO) == -1) {
			perror("dup2");
			exit(EXIT_FAILURE);
		}

		// Close unused file descriptors
		close(pipefd[0]);
		close(pipefd[1]);

		// Execute cmd1
		exit(parse_command(cmd2, level + 1, father));
	}

	// Parent process
	// Close the pipe file descriptors
	close(pipefd[0]);
	close(pipefd[1]);

	// Wait for both child processes to finish
	waitpid(pid1, &status, 0);
	waitpid(pid2, &status, 0);

	// Return true or false based on the exit status of cmd2
	if (WIFEXITED(status))
		return WEXITSTATUS(status);

	return 0;
}

/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father)
{
	int tmp;

	if (c->op == OP_NONE)
		return parse_simple(c->scmd, level, father);

	switch (c->op) {
	case OP_SEQUENTIAL:
		/* Execute the commands one after the other. */
		parse_command(c->cmd1, level + 1, c);
		return parse_command(c->cmd2, level + 1, c);

	case OP_PARALLEL:
		/* Execute the commands simultaneously. */
		return run_in_parallel(c->cmd1, c->cmd2, level + 1, c);

	case OP_CONDITIONAL_NZERO:
		/* Execute the second command only if the first one
		 * returns non zero.
		 */
		tmp = parse_command(c->cmd1, level + 1, c);
		if (tmp)
			return parse_command(c->cmd2, level + 1, c);
		break;

	case OP_CONDITIONAL_ZERO:
		/* Execute the second command only if the first one
		 * returns zero.
		 */
		tmp = parse_command(c->cmd1, level + 1, c);
		if (!tmp)
			return parse_command(c->cmd2, level + 1, c);
		break;

	case OP_PIPE:
		/* Redirect the output of the first command to the
		 * input of the second.
		 */
		return run_on_pipe(c->cmd1, c->cmd2, level + 1, c);

	default:
		return SHELL_EXIT;
	}

	return 0;
}
