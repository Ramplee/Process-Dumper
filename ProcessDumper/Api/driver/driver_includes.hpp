#pragma warning (disable: 4091 6328 6031)
#pragma once

/**
 * @file driver_includes.hpp
 * @brief Includes necessary headers and defines macros for logging.
 */

#include <Windows.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <stdio.h>
#include <assert.h>
#include "../xor.h"

#define FILENAMES_ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : \
(strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1 : __FILE__))

 /**
  * @brief Logging macro to output messages with the "Usermode" prefix.
  *
  * @param fmt The format string for the message.
  * @param ... Additional arguments for the format string.
  */
#define log(fmt, ...) \
printf(skCrypt("[Usermode] - [%s:%d] " fmt "\n"), FILENAMES_, __LINE__, ##__VA_ARGS__)

  /**
   * @brief Logging macro to output a new line with a custom message.
   *
   * @param fmt The format string for the message.
   */
#define log_new_line(fmt) \
printf(skCrypt("[%s:%d] " fmt "\n"), FILENAMES_, __LINE__)
