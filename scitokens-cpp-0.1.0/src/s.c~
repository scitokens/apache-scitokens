//#include <iostream>
#include "scitokens.h"
//#include "scitokens-cpp-0.1.0/src/scitokens.h"
//#include <scitscitokens.h>
#include <stdio.h>
#include <stdlib.h>
//#include <SciTokens>
//#include <sys/types.h>
//#include <cassert>
//#include <cstdio>
//#include <cstring>
//#include <vector>
//#include <sstream>
//#include <string>
//#include <map>
//#include <memory>
//#include <unistd.h>

//using namespace std;  // NOLINT

typedef struct {
  float a;
} ShapeClass;


//todo parse request, apr_table_get
int main(){
  SciToken scitoken;//malloc here?
  ShapeClass *test;
  // scitoken = malloc(sizeof(SciToken));
  //test = malloc(sizeof(ShapeClass));
  //test->a = 3;
  //printf("%d",test->a);
  const char *auth_line = "123";//incorrect input val so not defined?
  char *err_msg= NULL;
  char **null_ended_list= NULL; //maybe it is here bad practice
  int a;
  a = scitoken_deserialize(auth_line, &scitoken, null_ended_list, &err_msg);
  //scitoken_destroy(scitoken);
  //free(scitoken);
  printf("%s",err_msg);
}
