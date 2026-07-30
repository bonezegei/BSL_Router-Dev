#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include "bsl.h"

/* ================================================================================
   BSL CORE STRUCTS & MACROS
================================================================================ */
#if defined(_WIN32)
    #define EXPORT_API __declspec(dllexport)
    #ifndef __MINGW32__
        #define strdup _strdup
    #endif
#else
    #define EXPORT_API __attribute__((visibility("default")))
#endif

#ifndef VAL_OBJ
#define VAL_OBJ 5 
#endif

typedef Value (*CallInterpFn)(Function*, int, Value*, Env**);
static CallInterpFn g_call_interp = NULL;

EXPORT_API void bzg_native_init(void *fn) { 
    g_call_interp = (CallInterpFn)fn; 
}

/* ================================================================================
   OBJECT-ORIENTED SCRIPTING LAYER HELPERS
================================================================================ */
void add_native_method(Value* obj, const char* name, Value (*native_ptr)(int, Value*, Env**), int param_count) {
    Env* prop = (Env*)malloc(sizeof(Env));
    memset(prop, 0, sizeof(Env));
    strncpy(prop->name, name, 64);
    Function* f = (Function*)malloc(sizeof(Function));
    memset(f, 0, sizeof(Function));
    f->is_native = 1;
    f->native_ptr = native_ptr;
    strncpy(f->name, name, 64);
    f->param_count = param_count;
    prop->val = make_func(f);
    prop->next = obj->obj_props; 
    obj->obj_props = prop;
}

static void set_obj_prop(Value* obj, const char* name, Value val) {
    if (!obj || obj->type != VAL_OBJ) return;
    Env* curr = obj->obj_props;
    while (curr) {
        if (strcmp(curr->name, name) == 0) {
            curr->val = val;
            return;
        }
        curr = curr->next;
    }
    Env* prop = (Env*)malloc(sizeof(Env));
    if (!prop) return;
    memset(prop, 0, sizeof(Env));
    strncpy(prop->name, name, 64);
    prop->val = val;
    prop->next = obj->obj_props;
    obj->obj_props = prop;
}

static Value get_obj_prop(const Value* obj, const char* name) {
    if (!obj || obj->type != VAL_OBJ) return make_null();
    Env* curr = obj->obj_props;
    while (curr) {
        if (strcmp(curr->name, name) == 0) return curr->val;
        curr = curr->next;
    }
    return make_null();
}

static int resolve_router_id(Value val) {
    if (val.type == VAL_NUM) return (int)val.num;
    if (val.type == VAL_OBJ) {
        Value id_val = get_obj_prop(&val, "_id");
        if (id_val.type == VAL_NUM) return (int)id_val.num;
    }
    return 0; 
}

/* ================================================================================
   ROUTER SYSTEM CORE
================================================================================ */
#define MAX_ROUTERS 64
#define MAX_ROUTES 128
#define MAX_IFACES 16
#define MAX_FLOWS 256

typedef struct {
    uint32_t dest;
    uint32_t mask;
    char next_hop[16];
    char iface[16];
} Route;

typedef struct {
    char name[16];
    uint32_t ip;
    uint32_t mask;
    uint32_t limit_bps;     /* QoS: Bytes per second limit (0 = unlimited) */
    uint32_t current_bytes; /* QoS: Bytes transferred in current second window */
    time_t last_reset;      /* QoS: Timestamp of last bucket reset */
} Interface;

typedef struct {
    uint32_t src;
    uint32_t dst;
    uint32_t total_bytes;
    uint32_t hits;
    time_t last_seen;
} ActiveFlow;

typedef struct {
    int id;
    Route routes[MAX_ROUTES];
    int route_count;
    Interface ifaces[MAX_IFACES];
    int iface_count;
    ActiveFlow flows[MAX_FLOWS];
    int flow_count;
} RouterCtx;

static RouterCtx* router_registry[MAX_ROUTERS] = {NULL};
static int next_router_id = 1;

/* Helpers for IP Conversion */
static uint32_t ip_to_int(const char* ip) {
    unsigned int a, b, c, d;
    if (sscanf(ip, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
        return (a << 24) | (b << 16) | (c << 8) | d;
    }
    return 0;
}

static void int_to_ip(uint32_t ip, char* buf) {
    sprintf(buf, "%u.%u.%u.%u", (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
}

static int get_args_offset(const char* func_name, int argc, Value* argv, int* id_out, int* param_start) {
    for (int i = 0; i < argc; i++) {
        int id = resolve_router_id(argv[i]);
        if (id > 0) { 
            *id_out = id; 
            if (i == 0) *param_start = 1; 
            else if (i == argc - 1) *param_start = 0;
            else *param_start = i + 1;
            return 1; 
        }
    }
    printf("[C Layer Error] %s: Could not locate 'this' context!\n", func_name);
    return 0;
}

/* ================================================================================
   DYNAMIC NATIVE METHODS
================================================================================ */

static Value method_addInterface(int argc, Value* argv, Env** envp) {
    int id = 0, p = 0;
    if (!get_args_offset("addInterface", argc, argv, &id, &p)) return make_num(0);
    if ((argc - p) < 3) return make_num(0);
    
    RouterCtx* ctx = NULL;
    for (int i = 0; i < MAX_ROUTERS; i++) if (router_registry[i] && router_registry[i]->id == id) { ctx = router_registry[i]; break; }
    if (!ctx || ctx->iface_count >= MAX_IFACES) return make_num(0);

    Interface* iface = &ctx->ifaces[ctx->iface_count++];
    strncpy(iface->name, argv[p].str, 15);
    iface->name[15] = '\0';
    iface->ip = ip_to_int(argv[p+1].str);
    iface->mask = ip_to_int(argv[p+2].str);
    iface->limit_bps = 0;
    iface->current_bytes = 0;
    iface->last_reset = time(NULL);

    if (ctx->route_count < MAX_ROUTES) {
        Route* r = &ctx->routes[ctx->route_count++];
        r->dest = iface->ip & iface->mask; 
        r->mask = iface->mask;
        strcpy(r->next_hop, "0.0.0.0");
        strncpy(r->iface, iface->name, 15);
    }
    return make_num(1);
}

/* QoS: setBandwidth(ifaceName, bytesPerSecond) */
static Value method_setBandwidth(int argc, Value* argv, Env** envp) {
    int id = 0, p = 0;
    if (!get_args_offset("setBandwidth", argc, argv, &id, &p)) return make_num(0);
    if ((argc - p) < 2 || argv[p].type != VAL_STR || argv[p+1].type != VAL_NUM) return make_num(0);

    RouterCtx* ctx = NULL;
    for (int i = 0; i < MAX_ROUTERS; i++) if (router_registry[i] && router_registry[i]->id == id) { ctx = router_registry[i]; break; }
    if (!ctx) return make_num(0);

    for (int i = 0; i < ctx->iface_count; i++) {
        if (strcmp(ctx->ifaces[i].name, argv[p].str) == 0) {
            ctx->ifaces[i].limit_bps = (uint32_t)argv[p+1].num;
            return make_num(1);
        }
    }
    return make_num(0);
}

static Value method_addRoute(int argc, Value* argv, Env** envp) {
    int id = 0, p = 0;
    if (!get_args_offset("addRoute", argc, argv, &id, &p)) return make_num(0);
    if ((argc - p) < 4) return make_num(0);

    RouterCtx* ctx = NULL;
    for (int i = 0; i < MAX_ROUTERS; i++) if (router_registry[i] && router_registry[i]->id == id) { ctx = router_registry[i]; break; }
    if (!ctx || ctx->route_count >= MAX_ROUTES) return make_num(0);

    Route* r = &ctx->routes[ctx->route_count++];
    r->dest = ip_to_int(argv[p].str);
    r->mask = ip_to_int(argv[p+1].str);
    strncpy(r->next_hop, argv[p+2].str, 15);
    strncpy(r->iface, argv[p+3].str, 15);
    return make_num(1);
}

/* route(destIpStr, [srcIpStr], [packetSizeBytes]) */
static Value method_routePacket(int argc, Value* argv, Env** envp) {
    int id = 0, p = 0;
    if (!get_args_offset("route", argc, argv, &id, &p)) return make_null();
    if ((argc - p) < 1 || argv[p].type != VAL_STR) return make_null();

    uint32_t target = ip_to_int(argv[p].str);
    uint32_t src_ip = ((argc - p) >= 2 && argv[p+1].type == VAL_STR) ? ip_to_int(argv[p+1].str) : 0;
    uint32_t pkt_size = ((argc - p) >= 3 && argv[p+2].type == VAL_NUM) ? (uint32_t)argv[p+2].num : 64; /* Default 64 bytes */

    RouterCtx* ctx = NULL;
    for (int i = 0; i < MAX_ROUTERS; i++) if (router_registry[i] && router_registry[i]->id == id) { ctx = router_registry[i]; break; }
    if (!ctx) return make_null();

    /* 1. Longest Prefix Match (LPM) */
    Route* best_match = NULL;
    uint32_t best_mask = 0;
    for (int i = 0; i < ctx->route_count; i++) {
        Route* r = &ctx->routes[i];
        if ((target & r->mask) == (r->dest & r->mask)) {
            if (!best_match || r->mask >= best_mask) { best_match = r; best_mask = r->mask; }
        }
    }
    if (!best_match) return make_null(); 

    /* 2. Bandwidth Check (QoS Token Bucket) */
    Interface* target_iface = NULL;
    for (int i = 0; i < ctx->iface_count; i++) {
        if (strcmp(ctx->ifaces[i].name, best_match->iface) == 0) { target_iface = &ctx->ifaces[i]; break; }
    }

    if (target_iface && target_iface->limit_bps > 0) {
        time_t now = time(NULL);
        if (now != target_iface->last_reset) {
            target_iface->current_bytes = 0;
            target_iface->last_reset = now;
        }
        if (target_iface->current_bytes + pkt_size > target_iface->limit_bps) {
            printf("[QoS] Packet dropped on %s! Rate limit exceeded.\n", target_iface->name);
            return make_null(); /* DROP */
        }
        target_iface->current_bytes += pkt_size;
    }

    /* 3. State Tracking (Active Connections) */
    if (src_ip != 0) {
        int flow_found = 0;
        for (int i = 0; i < ctx->flow_count; i++) {
            if (ctx->flows[i].src == src_ip && ctx->flows[i].dst == target) {
                ctx->flows[i].total_bytes += pkt_size;
                ctx->flows[i].hits++;
                ctx->flows[i].last_seen = time(NULL);
                flow_found = 1; break;
            }
        }
        if (!flow_found && ctx->flow_count < MAX_FLOWS) {
            ActiveFlow* f = &ctx->flows[ctx->flow_count++];
            f->src = src_ip;
            f->dst = target;
            f->total_bytes = pkt_size;
            f->hits = 1;
            f->last_seen = time(NULL);
        }
    }

    /* 4. Return Routing Decision */
    Value result = make_obj();
    set_obj_prop(&result, "nextHop", make_str(strdup(best_match->next_hop)));
    set_obj_prop(&result, "interface", make_str(strdup(best_match->iface)));
    return result;
}

/* getRoutes() -> Returns array of objects */
static Value method_getRoutes(int argc, Value* argv, Env** envp) {
    int id = 0, p = 0;
    if (!get_args_offset("getRoutes", argc, argv, &id, &p)) return make_null();

    RouterCtx* ctx = NULL;
    for (int i = 0; i < MAX_ROUTERS; i++) if (router_registry[i] && router_registry[i]->id == id) { ctx = router_registry[i]; break; }
    if (!ctx) return make_null();

    Value* els = (Value*)malloc(sizeof(Value) * ctx->route_count);
    for (int i = 0; i < ctx->route_count; i++) {
        Value route_obj = make_obj();
        char dest_str[32], mask_str[32];
        int_to_ip(ctx->routes[i].dest, dest_str);
        int_to_ip(ctx->routes[i].mask, mask_str);
        
        set_obj_prop(&route_obj, "dest", make_str(strdup(dest_str)));
        set_obj_prop(&route_obj, "mask", make_str(strdup(mask_str)));
        set_obj_prop(&route_obj, "nextHop", make_str(strdup(ctx->routes[i].next_hop)));
        set_obj_prop(&route_obj, "interface", make_str(strdup(ctx->routes[i].iface)));
        els[i] = route_obj;
    }
    Array* arr = (Array*)malloc(sizeof(Array));
    arr->elements = els;
    arr->length = ctx->route_count;
    return make_arr(arr);
}

/* getActiveFlows() -> Returns array of connection states */
static Value method_getActiveFlows(int argc, Value* argv, Env** envp) {
    int id = 0, p = 0;
    if (!get_args_offset("getActiveFlows", argc, argv, &id, &p)) return make_null();

    RouterCtx* ctx = NULL;
    for (int i = 0; i < MAX_ROUTERS; i++) if (router_registry[i] && router_registry[i]->id == id) { ctx = router_registry[i]; break; }
    if (!ctx) return make_null();

    Value* els = (Value*)malloc(sizeof(Value) * ctx->flow_count);
    for (int i = 0; i < ctx->flow_count; i++) {
        Value flow_obj = make_obj();
        char src_str[32], dst_str[32];
        int_to_ip(ctx->flows[i].src, src_str);
        int_to_ip(ctx->flows[i].dst, dst_str);
        
        set_obj_prop(&flow_obj, "src", make_str(strdup(src_str)));
        set_obj_prop(&flow_obj, "dest", make_str(strdup(dst_str)));
        set_obj_prop(&flow_obj, "bytes", make_num(ctx->flows[i].total_bytes));
        set_obj_prop(&flow_obj, "hits", make_num(ctx->flows[i].hits));
        els[i] = flow_obj;
    }
    Array* arr = (Array*)malloc(sizeof(Array));
    arr->elements = els;
    arr->length = ctx->flow_count;
    return make_arr(arr);
}

/* ================================================================================
   ROUTER FACTORY
================================================================================ */
EXPORT_API Value router_create(int argc, Value *argv, Env** envp) {
    RouterCtx *ctx = (RouterCtx*)malloc(sizeof(RouterCtx));
    if (!ctx) return make_null();
    memset(ctx, 0, sizeof(RouterCtx));
    ctx->id = next_router_id++;
    int placed = 0;
    for (int i = 0; i < MAX_ROUTERS; i++) if (!router_registry[i]) { router_registry[i] = ctx; placed = 1; break; } 
    if (!placed) { free(ctx); return make_null(); }
    
    Value obj = make_obj();
    set_obj_prop(&obj, "_id", make_num((double)ctx->id));
    
    add_native_method(&obj, "addInterface", method_addInterface, 3);
    add_native_method(&obj, "setBandwidth", method_setBandwidth, 2);
    add_native_method(&obj, "addRoute", method_addRoute, 4);
    add_native_method(&obj, "route", method_routePacket, 3);
    add_native_method(&obj, "getRoutes", method_getRoutes, 0);
    add_native_method(&obj, "getActiveFlows", method_getActiveFlows, 0);
    
    return obj;
}

EXPORT_API Value createRouterMgr(int argc, Value *argv, Env** envp) {
    Value mgr = make_obj();
    add_native_method(&mgr, "create", router_create, 0); 
    return mgr;
}