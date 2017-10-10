- evhtp_set_glob_cb(m_evhtp,path.c_str(), void(cb*)(evhtp_request_t* req, void* arg), void *arg);
- evhtp_request_t 
``
typedef struct evhtp_request_s evhtp_request_t
``

- evhtp_request_s
``
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
``
