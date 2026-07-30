typedef enum { VAL_NULL, VAL_NUM, VAL_STR, VAL_FUNC, VAL_ARR, VAL_OBJ } ValueType;

typedef struct Node Node; /* forward (we only build small call nodes) */
typedef struct Function Function;
typedef struct Env Env;
typedef struct Array Array;

typedef struct Value {
    ValueType type;
    double num;
    char *str;
    Function *func;
    Array *arr;
    Env *obj_props;
} Value;

struct Array { Value *elements; int length; };

struct Env { char name[64]; Value val; Env *next; Env *parent; };

typedef Value (*NativeFn)(int argc, Value* argv, Env** envp);

struct Function {
    char name[64];
    char params[8][64];
    int param_count;
    Node *body;
    Env *closure;
    Node *classdef;
    int is_native;
    NativeFn native_ptr;
};

enum {
    NODE_NUM, NODE_STR, NODE_VAR, NODE_ASSIGN, NODE_BINOP,
    NODE_PRINT, NODE_IF, NODE_WHILE, NODE_FOR,
    NODE_BLOCK, NODE_FUNCDEF, NODE_FUNCCALL, NODE_RETURN,
    NODE_ARRAY, NODE_ARRACCESS, NODE_CLASSDEF,
    NODE_NEW,
    NODE_PROPACCESS,
    NODE_UNARY,
    NODE_CONSTRUCTOR
};

struct Node {
    int kind;
    double num;
    char *str;
    char name[64];
    int op; /* TokenType not needed here */
    Node *left, *right;
    Node *cond, *thenb, *elseb;
    Node *init, *update, *body;
    Node **stmts; int stmt_count;
    Node **args; int arg_count;
    char params[8][64];
    int param_count;
    Node *index;
    char prop_name[64];
    Node **fields; int field_count;
};

/* Minimal constructors (compatible with the interpreter's helpers). These
 * are intentionally simple wrappers and avoid allocating GC-managed copies
 * of strings — the interpreter often duplicates strings when needed.
 */
static Value make_null(){ Value v={VAL_NULL,0,NULL,NULL,NULL,NULL}; return v; }
static Value make_num(double x){ Value v={VAL_NUM,x,NULL,NULL,NULL,NULL}; return v; }
static Value make_str(const char *s){ Value v={VAL_STR,0,(char*)s,NULL,NULL,NULL}; return v; }
static Value make_func(Function *f){ Value v={VAL_FUNC,0,NULL,f,NULL,NULL}; return v; }
static Value make_arr(Array *a){ Value v={VAL_ARR,0,NULL,NULL,a,NULL}; return v; }
static Value make_obj(){ Value v={VAL_OBJ,0,NULL,NULL,NULL,NULL}; return v; }


#if defined(_WIN32)
    // Windows export
   
    #define EXPORT_API __declspec(dllexport)
     
#else
    // Linux/macOS export
    #define EXPORT_API __attribute__((visibility("default")))
#endif


//typedef Value (*CallInterpFn)(Function*, int, Value*, Env**);
//static CallInterpFn g_call_interp = NULL;
//
//EXPORT_API void bzg_native_init(void* fn) {
//    g_call_interp = (CallInterpFn)fn;
//}