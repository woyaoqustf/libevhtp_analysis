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



_evhtp_accept_cb(evserv_t

_evhtp_conection_new

```
struct evhtp_connection_s {
    evhtp_t  * htp;
    evbase_t * evbase;
    evbev_t  * bev;
#ifndef EVHTP_DISABLE_EVTHR
    evthr_t * thread;
#endif
#ifndef EVHTP_DISABLE_SSL
    evhtp_ssl_t * ssl;
#endif
    evhtp_hooks_t   * hooks;
    htparser        * parser;
    event_t         * resume_ev;
    struct sockaddr * saddr;
    struct timeval    recv_timeo;          /**< conn read timeouts (overrides global) */
    struct timeval    send_timeo;          /**< conn write timeouts (overrides global) */
    evutil_socket_t   sock;
    evhtp_request_t * request;             /**< the request currently being processed */
    uint64_t          max_body_size;
    uint64_t          body_bytes_read;
    uint64_t          num_requests;
    evhtp_type        type;                /**< server or client */
    uint8_t           error           : 1,
                      owner           : 1, /**< set to 1 if this structure owns the bufferevent */
                      vhost_via_sni   : 1, /**< set to 1 if the vhost was found via SSL SNI */
                      paused          : 1, /**< this connection has been marked as paused */
                      connected       : 1, /**< client specific - set after successful connection */
                      waiting         : 1, /**< used to make sure resuming  happens AFTER sending a reply */
                      free_connection : 1,
                      keepalive       : 1; /**< set to 1 after the first request has been processed and the connection is kept open */
    struct evbuffer * scratch_buf;         /**< always zero'd out after used */

#ifdef EVHTP_FUTURE_USE
    TAILQ_HEAD(, evhtp_request_s) pending; /**< client pending data */
#endif
};

struct htparser {
    htpparse_error error;
    parser_state   state;
    parser_flags   flags;
    eval_hdr_val   heval;

    htp_type   type;
    htp_scheme scheme;
    htp_method method;

    unsigned char multipart;
    unsigned char major;
    unsigned char minor;
    uint64_t      content_len;      /* this gets decremented as data passes through */
    uint64_t      orig_content_len; /* this contains the original length of the body */
    uint64_t      bytes_read;
    uint64_t      total_bytes_read;
    unsigned int  status;           /* only for responses */
    unsigned int  status_count;     /* only for responses */

    char * scheme_offset;
    char * host_offset;
    char * port_offset;
    char * path_offset;
    char * args_offset;

    void * userdata;

    size_t buf_idx;
    /* Must be last since htparser_init memsets up to the offset of this buffer */
    char buf[PARSER_STACK_MAX];
};

enum htp_scheme {
    htp_scheme_none = 0,
    htp_scheme_ftp,
    htp_scheme_http,
    htp_scheme_https,
    htp_scheme_nfs,
    htp_scheme_unknown
};

```

```
static void
_evhtp_accept_cb(evserv_t * serv, int fd, struct sockaddr * s, int sl, void * arg) {
    evhtp_t            * htp = arg;
    evhtp_connection_t * connection;

    if (evhtp_unlikely(!(connection = _evhtp_connection_new(htp, fd, evhtp_type_server)))) {
        return;
    }

    htp_log_debug("fd = %d, conn = %p", fd, connection);

    connection->saddr = malloc(sl);
    evhtp_alloc_assert(connection->saddr);

    memcpy(connection->saddr, s, sl);

#ifndef EVHTP_DISABLE_EVTHR
    if (htp->thr_pool != NULL) {
        if (evthr_pool_defer(htp->thr_pool,
                             _evhtp_run_in_thread, connection) != EVTHR_RES_OK) {
            evutil_closesocket(connection->sock);
            evhtp_connection_free(connection);

            return;
        }

        return;
    }
#endif
    connection->evbase = htp->evbase;

    if (_evhtp_connection_accept(htp->evbase, connection) < 0) {
        evhtp_connection_free(connection);

        return;
    }

    if (_evhtp_run_post_accept(htp, connection) < 0) {
        evhtp_connection_free(connection);

        return;
    }
} /* _evhtp_accept_cb */
```
- _evhtp_connection_accept 设置bufferedevent/sslbuf, timeout&timeoutcb
```
static int
_evhtp_connection_accept(evbase_t * evbase, evhtp_connection_t * connection) {
    struct timeval * c_recv_timeo;
    struct timeval * c_send_timeo;

    if (_evhtp_run_pre_accept(connection->htp, connection) < 0) {
        evutil_closesocket(connection->sock);

        return -1;
    }

#ifndef EVHTP_DISABLE_SSL
    if (connection->htp->ssl_ctx != NULL) {
        connection->ssl = SSL_new(connection->htp->ssl_ctx);
        connection->bev = bufferevent_openssl_socket_new(evbase,
                                                         connection->sock,
                                                         connection->ssl,
                                                         BUFFEREVENT_SSL_ACCEPTING,
                                                         connection->htp->bev_flags);
        SSL_set_app_data(connection->ssl, connection);
        goto end;
    }
#endif

    connection->bev = bufferevent_socket_new(evbase,
                                             connection->sock,
                                             connection->htp->bev_flags);

    htp_log_debug("enter sock=%d\n", connection->sock);

#ifndef EVHTP_DISABLE_SSL
end:
#endif

    if (connection->recv_timeo.tv_sec || connection->recv_timeo.tv_usec) {
        c_recv_timeo = &connection->recv_timeo;
    } else if (connection->htp->recv_timeo.tv_sec ||
               connection->htp->recv_timeo.tv_usec) {
        c_recv_timeo = &connection->htp->recv_timeo;
    } else {
        c_recv_timeo = NULL;
    }

    if (connection->send_timeo.tv_sec || connection->send_timeo.tv_usec) {
        c_send_timeo = &connection->send_timeo;
    } else if (connection->htp->send_timeo.tv_sec ||
               connection->htp->send_timeo.tv_usec) {
        c_send_timeo = &connection->htp->send_timeo;
    } else {
        c_send_timeo = NULL;
    }

    evhtp_connection_set_timeouts(connection, c_recv_timeo, c_send_timeo);

    connection->resume_ev = event_new(evbase, -1, EV_READ | EV_PERSIST,
                                      _evhtp_connection_resumecb, connection);
    event_add(connection->resume_ev, NULL);

    bufferevent_enable(connection->bev, EV_READ);
    bufferevent_setcb(connection->bev,
                      _evhtp_connection_readcb,
                      _evhtp_connection_writecb,
                      _evhtp_connection_eventcb, connection);

    return 0;
}     /* _evhtp_connection_accept */

```
- _evhtp_connection_resumecb
```
static void
_evhtp_connection_resumecb(int fd, short events, void * arg) {
    evhtp_connection_t * c = arg;

    c->paused = 0;

    if (c->request) {
        c->request->status = EVHTP_RES_OK;
    }

    if (c->free_connection == 1) {
        evhtp_connection_free(c);

        return;
    }

    /* XXX this is a hack to show a potential fix for issues/86, the main indea
     * is that you call resume AFTER you have sent the reply (not BEFORE).
     *
     * When it has been decided this is a proper fix, the pause bit should be
     * changed to a state-type flag.
     */

    if (evbuffer_get_length(bufferevent_get_output(c->bev))) {
        bufferevent_enable(c->bev, EV_WRITE);
        c->waiting = 1;
    } else {
        bufferevent_enable(c->bev, EV_READ | EV_WRITE);
        _evhtp_connection_readcb(c->bev, c);
    }
}


```
## TODO Vhost
