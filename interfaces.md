- evhtp_set_glob_cb(m_evhtp,path.c_str(), void(cb*)(evhtp_request_t* req, void* arg), void *arg);
- evhtp_request_t 
``
typedef struct evhtp_request_s evhtp_request_t
``

- evhtp_request_s  
```
/**
 * @brief a structure containing all information for a http request.
 */
struct evhtp_request_s {
    evhtp_t            * htp;           /**< the parent evhtp_t structure */
    evhtp_connection_t * conn;          /**< the associated connection */
    evhtp_hooks_t      * hooks;         /**< request specific hooks */
    evhtp_uri_t        * uri;           /**< request URI information */
    evbuf_t            * buffer_in;     /**< buffer containing data from client */
    evbuf_t            * buffer_out;    /**< buffer containing data to client */
    evhtp_headers_t    * headers_in;    /**< headers from client */
    evhtp_headers_t    * headers_out;   /**< headers to client */
    evhtp_proto          proto;         /**< HTTP protocol used */
    htp_method           method;        /**< HTTP method used */
    evhtp_res            status;        /**< The HTTP response code or other error conditions */
    uint8_t              keepalive : 1, /**< set to 1 if the connection is keep-alive */
                         finished  : 1, /**< set to 1 if the request is fully processed */
                         chunked   : 1, /**< set to 1 if the request is chunked */
                         error     : 1, /**< set if any sort of error has occurred. */
                         pad       : 4; /**< to be used in evhtp2 for new stuff */

    evhtp_callback_cb cb;               /**< the function to call when fully processed */
    void            * cbarg;            /**< argument which is passed to the cb function */

    TAILQ_ENTRY(evhtp_request_s) next;
};
```

- evhtp_header_find
```
evhtp_header_find(htp_req->headers_in, char * key)

#define evhtp_header_find evhtp_kv_find
```

```
struct evhtp_defaults_s {
    evhtp_callback_cb    cb;
    evhtp_pre_accept_cb  pre_accept;
    evhtp_post_accept_cb post_accept;
    void               * cbarg;
    void               * pre_accept_cbarg;
    void               * post_accept_cbarg;
};

struct evhtp_s {
      evhtp_t  * parent;                  /**< only when this is a vhost */
      evbase_t * evbase;                  /**< the initialized event_base */
      evserv_t * server;                  /**< the libevent listener struct */
      char     * server_name;             /**< the name included in Host: responses */
      void     * arg;                     /**< user-defined evhtp_t specific arguments */
      int        bev_flags;               /**< bufferevent flags to use on bufferevent_*_socket_new() */
      uint64_t   max_body_size;
      uint64_t   max_keepalive_requests;
      uint8_t    disable_100_cont    : 1, /**< if set, evhtp will not respond to Expect: 100-continue */
          ¦      enable_reuseport    : 1,
          ¦      enable_nodelay      : 1,
          ¦      enable_defer_accept : 1,
          ¦      pad                 : 4;

      int parser_flags;                   /**< default query flags to alter 'strictness' (see EVHTP_PARSE_QUERY_FLAG_*) */

  #ifndef EVHTP_DISABLE_SSL
      evhtp_ssl_ctx_t * ssl_ctx;          /**< if ssl enabled, this is the servers CTX */
      evhtp_ssl_cfg_t * ssl_cfg;
  #endif

  #ifndef EVHTP_DISABLE_EVTHR
      evthr_pool_t    * thr_pool;         /**< connection threadpool */
      pthread_mutex_t * lock;             /**< parent lock for add/del cbs in threads */

      evhtp_thread_init_cb thread_init_cb;
      evhtp_thread_exit_cb thread_exit_cb;

      /* keep backwards compat because I'm dumb and didn't
       * make these structs private
       */
      #define thread_init_cbarg thread_cbarg
      void * thread_cbarg;
  #endif
      evhtp_callbacks_t * callbacks;
      evhtp_defaults_t    defaults;

      struct timeval recv_timeo;
      
      TAILQ_HEAD(, evhtp_alias_s) aliases;
      TAILQ_HEAD(, evhtp_s) vhosts;
      TAILQ_ENTRY(evhtp_s) next_vhost;
  };
```

## TODO Vhost
