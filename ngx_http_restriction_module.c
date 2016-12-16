/*
 * 利用红黑树、共享内存、限制客户端访问频率、队列长度查询
 * 是一个很好的学习nginx模块开发的例子，抛砖迎玉
 * author: jiakai
 * email: hnjiakai@qq.com
 * date: 2016-12-15
 */

#define __DEBUG__
#ifdef  __DEBUG__
#define DEBUG(format,...) printf("%05d:%38s: "format" \n", __LINE__,__FUNCTION__, ##__VA_ARGS__)
#else
#define DEBUG(format,...)
#endif


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_connection.h>
#include <netinet/in.h>


/*存储访问信息的struct*/
typedef struct {

  u_char   rbtree_node_data ;/*ngx_rbtree_node_t的data*/
  ngx_queue_t queue; /*先后顺序串联节点，方便淘汰*/
  ngx_msec_t last ;/*上次访问时间，毫秒精度*/
  u_short len;/*客户端ip+url长度*/
  u_char data[1];/*保存ip+url字符串*/

} ngx_http_restriction_node_t ;


/* 保存在共享内存中 */
typedef struct {
  ngx_rbtree_t rbtree;   /*红黑树首地址*/
  ngx_rbtree_node_t sentinel; /*红黑树哨兵*/
  ngx_queue_t queue;/*淘汰队列首地址*/
} ngx_http_restriction_shm_t;

/*模块的配置文件*/
typedef struct
{
  ngx_int_t interval;  /*时间间隔*/
  ssize_t shmsize;   /*共享内存大小*/
  ngx_slab_pool_t *shpool;   /*共享内存池首地址*/
  ngx_http_restriction_shm_t *sh; /*队列和树重要信息*/
} ngx_http_restriction_main_conf_t;

/*存储状态信息信息的struct*/
typedef struct {

} ngx_http_restriction_status_conf_t ;


/*
typedef struct {
    ngx_str_t    test;          // test选项的值将存储在这里
} ngx_http_restriction_loc_conf_t;
*/


/*红黑树节点插入*/
static void ngx_http_restriction_rbtree_insert_value(ngx_rbtree_node_t *root , ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
/*红黑树检索节点*/
static ngx_int_t ngx_http_restriction_rbtree_lookup(ngx_http_request_t *r , ngx_http_restriction_main_conf_t *conf, ngx_uint_t hash , u_char* data, size_t len);

static void ngx_http_restriction_rbtree_expire(ngx_http_request_t *r, ngx_http_restriction_main_conf_t *conf);


static char* ngx_http_restriction_createmem(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);

static void* ngx_http_restriction_create_main_conf(ngx_conf_t *cf);

static ngx_int_t ngx_http_restriction_shm_init(ngx_shm_zone_t *shm_zone, void *data);

static ngx_int_t ngx_http_restriction_init(ngx_conf_t *cf);

static ngx_int_t ngx_http_restriction_handler(ngx_http_request_t *r);

static char * ngx_http_restriction_merge_conf(ngx_conf_t *cf, void *parent, void *child);

static char* ngx_http_restriction_status(ngx_conf_t *cf,  ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_restriction_status_handler(ngx_http_request_t *r);



static void * ngx_http_restriction_create_loc_conf(ngx_conf_t *cf){

    ngx_http_restriction_status_conf_t  *hlscf;

    hlscf = ngx_pcalloc(cf->pool, sizeof(ngx_http_restriction_status_conf_t));
    if (hlscf == NULL) {
        return NULL;
    }

    return hlscf;
}



static ngx_command_t  ngx_http_restriction_commands[] = {
  {
    ngx_string("restriction"),
    NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE2,
    ngx_http_restriction_createmem,
    //0, /*此处必须是0，而不是NGX_HTTP_LOC_CONF_OFFSET*/
    0,
    0,
    NULL
  },
  {
    ngx_string("restriction_status"),
    NGX_HTTP_MAIN_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
    ngx_http_restriction_status,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL
  },
  ngx_null_command
};

static ngx_http_module_t ngx_http_restriction_module_ctx = {
  NULL,
  ngx_http_restriction_init,
  ngx_http_restriction_create_main_conf,
  NULL,
  NULL,
  NULL,
  ngx_http_restriction_create_loc_conf,
  ngx_http_restriction_merge_conf
};


ngx_module_t ngx_http_restriction_module = {
  NGX_MODULE_V1,
  &ngx_http_restriction_module_ctx,
  ngx_http_restriction_commands,
  NGX_HTTP_MODULE,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NGX_MODULE_V1_PADDING

};




/*模块初始化*/
static ngx_int_t ngx_http_restriction_init(ngx_conf_t *cf) {

  DEBUG("cf %p", cf);

  ngx_http_handler_pt        *h;
  ngx_http_core_main_conf_t  *cmcf;
  cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
  DEBUG("cmcf %p", cmcf);
  /*设置模块在NXG_HTTP_PREACCESS_PHASE阶段介入*/
  h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
  if (h == NULL) {
    return NGX_ERROR ;
  }
  /*设置请求方法*/
  *h = ngx_http_restriction_handler ;
  DEBUG("end %p", h);
  return NGX_OK;
}





static char* ngx_http_restriction_status(ngx_conf_t *cf,  ngx_command_t *cmd, void *conf){

  ngx_http_core_loc_conf_t  *clcf;

  clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

  clcf->handler = ngx_http_restriction_status_handler;//处理方法指向report


  return NGX_CONF_OK ;

}


static ngx_int_t ngx_http_restriction_status_handler(ngx_http_request_t *r){



  ngx_http_restriction_main_conf_t  *conf ;
  conf = ngx_http_get_module_main_conf(r, ngx_http_restriction_module);



  /*计算下队列长度*/
  ngx_uint_t qlen = 0 ;
  ngx_queue_t                   *qt ;
  ngx_queue_t  *head;
  if (!ngx_queue_empty(&conf->sh->queue) ) {
    head = ngx_queue_head(&conf->sh->queue);
    qt = head ;
    do {
      if (qt == NULL) {
        break ;
      }

      size_t ts = offsetof(ngx_http_restriction_node_t, queue);

      ngx_http_restriction_node_t *tt =
        (ngx_http_restriction_node_t*)((char*)qt - ts);

      ++qlen ;
      DEBUG("data %s", tt->data);
      qt = qt->next;

    } while (qt != head);

  }


  DEBUG("queue length %ld", qlen);




  //下面输出返回结果
  //
  ngx_int_t rc =ngx_http_discard_request_body(r);

  if (rc != NGX_OK){
    return rc;
  }

  


  ngx_buf_t *b;
  u_char buffer[256];
  ngx_int_t len = 0;


  


  u_char *p;
  p = ngx_snprintf(buffer, 255, "queue length : %i", qlen);
  len = p - buffer;

  DEBUG("%p",p);

  //ngx_memcpy(b->pos,p,len+1);
  //
  //b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
  b=ngx_create_temp_buf(r->pool,len);
  if (b == NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to allocate response buffer.");
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  DEBUG(" string length %ld ",len);



  ngx_str_t type = ngx_string("text/plain");
  //ngx_str_t response=ngx_string("hello word!");
  r->headers_out.status=NGX_HTTP_OK ;
  r->headers_out.content_type=type;
  r->headers_out.content_length_n=len;
  rc =ngx_http_send_header(r);
  if( rc!= NGX_OK){
    return rc;
  }



  
  //b->pos = buffer;
  ngx_memcpy(b->pos,buffer,len);
  b->last = b->pos + len;
  //b->memory = 1;
  b->last_buf = 1;

  

  ngx_chain_t out;
  out.buf = b;
  out.next = NULL;

  DEBUG("send data");

  return ngx_http_output_filter(r, &out);

}



static ngx_int_t ngx_http_restriction_handler(ngx_http_request_t *r) {
  DEBUG("start");
  size_t           len ;
  uint32_t         hash ;
  ngx_int_t        rc;
  ngx_http_restriction_main_conf_t  *conf ;
  conf = ngx_http_get_module_main_conf(r, ngx_http_restriction_module);
  //test
  ngx_http_restriction_rbtree_expire(r, conf);

  rc = NGX_DECLINED ;
  if (conf->interval == -1) {
    return rc;
  }

  /*ip和uri*/
  len = r->connection->addr_text.len + r->uri.len;
  u_char *data = ngx_pcalloc(r->pool, len);
  ngx_memcpy(data, r->uri.data, r->uri.len);
  ngx_memcpy(data + r->uri.len, r->connection->addr_text.data, r->connection->addr_text.len);

  /*crc32算出hash码，作为红黑树的key*/
  hash = ngx_crc32_short(data, len);
  /*多进程操作共享内存，需要加锁*/
  ngx_shmtx_lock(&conf->shpool->mutex);
  //处理请求
  rc = ngx_http_restriction_rbtree_lookup(r, conf, hash, data, len);
  ngx_shmtx_unlock(&conf->shpool->mutex);



  DEBUG("end");

  return rc ;


}



/*查找红黑树*/
static ngx_int_t ngx_http_restriction_rbtree_lookup(ngx_http_request_t *r ,
    ngx_http_restriction_main_conf_t  *conf ,
    ngx_uint_t hash , u_char* data, size_t len) {

  DEBUG("start");

  size_t          size;
  ngx_int_t       rc;
  ngx_time_t      *tp;
  ngx_msec_t      now;
  ngx_msec_int_t  ms;
  ngx_rbtree_node_t    *node, *sentinel; 
  ngx_http_restriction_node_t  *lr;

  /*当前时间*/
  tp = ngx_timeofday();
  now = (ngx_msec_int_t) (tp->sec * 1000 + tp->msec);
  node = conf->sh->rbtree.root;
  sentinel = conf->sh->rbtree.sentinel;

  while (node != sentinel) {
    /*用key快速找*/
    if (hash < node->key) {
      node = node->left;
      continue;
    }
    if (hash > node->key ) {
      node = node->right;
      continue ;
    }

    /*hash == node->key*/
    lr = (ngx_http_restriction_node_t*) &node->data;
    /*比较ip+url字符串*/
    rc = ngx_memn2cmp(data, lr->data, len, (size_t)len);
    if (rc == 0) {
      /*找到访问记录*/
      ms = (ngx_msec_int_t)(now - lr->last);
      DEBUG(" ms %lu ", ms);
      DEBUG(" interval %lu ", conf->interval);
      /*比较时间，判断是否超时*/
      if (ms > conf->interval) {
        /*在设定时间之内，允许访问*/
        lr->last = now;
        /*红黑树中该节点不动，而将该节点移动到队列首，防止被淘汰*/
        ngx_queue_remove(&lr->queue);
        ngx_queue_insert_head(&conf->sh->queue, &lr->queue);

        /*允许向下执行*/
        DEBUG("NGX_DECLINED");
        return NGX_DECLINED;
      } else {
        /*访问过于频繁，403*/
        return NGX_HTTP_FORBIDDEN ;
      }
    }

    /*没找到的话继续*/
    node = (rc < 0) ? node->left : node->right;
  }

  /*到达这里说明没找到，node为哨兵节点*/
  /*申请一块连续内存*/
  //ngx_rbtree_node_t非data长度+ngx_http_restriction_node_t非data长度+总数据data长度
  //ngx_rbtree_node_t的data位置开始存储ngx_http_restriction_node_t
  //ngx_http_restriction_node_t的data位置开始存储字符串
  size = offsetof(ngx_rbtree_node_t, data) +
         offsetof(ngx_http_restriction_node_t, data) + len ;

  /*申请内存*/
  node = ngx_slab_alloc_locked(conf->shpool, size);
  if (node == NULL) {
    /*申请内存失败*/
    return NGX_ERROR ;
  }
  /*key 是ip+url的hash值*/
  node->key = hash ;
  lr = (ngx_http_restriction_node_t *) &node->data;
  lr->last = now;
  lr->len = (u_char)len;
  /*复制过来*/
  ngx_memcpy(lr->data, data, len);
  /*插入红黑树*/
  ngx_rbtree_insert(&conf->sh->rbtree, node);
  /*插入链表首*/
  ngx_queue_insert_head(&conf->sh->queue, &lr->queue);
  DEBUG("end");
  /*继续执行*/
  return NGX_DECLINED ;

}





/*淘汰过期数据*/
static void ngx_http_restriction_rbtree_expire(ngx_http_request_t *r
    , ngx_http_restriction_main_conf_t *conf) {

  DEBUG("start");

  ngx_time_t                    *tp;
  ngx_msec_t                    now;
  ngx_queue_t                   *q ;
  ngx_msec_int_t                ms;
  ngx_rbtree_node_t             *node;
  ngx_http_restriction_node_t   *lr;






  /*取出缓存时间*/
  tp = ngx_timeofday();
  now = (ngx_msec_t) (tp->sec * 1000 + tp->msec);

  /*循环淘汰,最新访问总在队列前面,queue为空或遇到不需要淘汰节点终止*/
  while (1) {

    DEBUG("search");
    if (ngx_queue_empty(&conf->sh->queue)) {
      return ;
    }
    DEBUG("search 2");
    /*从尾部开始,尾部是最老的记录*/
    q = ngx_queue_last(&conf->sh->queue);
    /*取出ngx_queue_t data的地址*/
    lr = ngx_queue_data(q, ngx_http_restriction_node_t, queue);
    DEBUG("lr %s", lr->data);
    /*向前找到ngx_rbtree_node_t*/
    /*ngx_http_restriction_node_t在ngx_rbtree_node_t的data后面,*/
    //连续内存块分配时gx_http_restriction_node_t是在offsetof(ngx_rbtree_node_t, data)位置
    //lr减去偏移量，得到ngx_rbtree_node_t地址
    DEBUG("%s", (u_char*)lr);
    node = (ngx_rbtree_node_t * ) ((u_char*)lr - offsetof(ngx_rbtree_node_t, data));

    /*计算时间差*/
    ms = (ngx_msec_int_t) (now - lr->last);

    if (ms < conf->interval) {
      /*到达最后一个有效的节点,终止*/
      return ;
    }

    /*移出淘汰的节点*/
    ngx_queue_remove(q);

    /*移出红黑树*/
    ngx_rbtree_delete(&conf->sh->rbtree, node);

    /*从共享内存中释放出来*/
    ngx_slab_free_locked(conf->shpool, node);

  }

  DEBUG("end");

}






static void* ngx_http_restriction_create_main_conf(ngx_conf_t *cf) {

  ngx_http_restriction_main_conf_t *conf;
  conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_restriction_main_conf_t));

  if (conf == NULL ) {
    return NGX_CONF_ERROR;
  }
  conf->interval = -1;
  conf->shmsize = -1;
  DEBUG("main conf %p ", conf);


  return conf ;

}





static char *
ngx_http_restriction_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
  DEBUG("merge config");
//  ngx_http_restriction_main_conf_t *prev = parent;
//  ngx_http_restriction_main_conf_t *conf = child;
//
//  if (conf->interval == 0) {
//    conf->interval = prev->interval;
//  }
//
//  if (conf->shmsize == 0) {
//    conf->shmsize = prev->shmsize;
//  }

  DEBUG("merge config end");
  return NGX_CONF_OK;
}


static char* ngx_http_restriction_createmem(ngx_conf_t *cf
    , ngx_command_t *cmd, void *conf) {


  ngx_str_t               *value;
  ngx_shm_zone_t          *shm_zone;

  DEBUG("cf %p", cf);

  /*ngx_http_restriction_creat_main_conf创建的*/
  DEBUG("conf %p ", conf);
  ngx_http_restriction_main_conf_t *mconf =
    (ngx_http_restriction_main_conf_t *)conf;
  DEBUG("mconf %p ", mconf);

  ngx_str_t name = ngx_string("slab_memory");

  DEBUG("name %s", name.data);

  /*解析配置参数*/
  value = cf->args->elts ;
  /*获取两次成功时间间隔*/
  //mconf->interval = 1000 * ngx_atoi(value[1].data, value[1].len);
  //单位改成毫秒
  mconf->interval =  ngx_atoi(value[1].data, value[1].len);
  DEBUG(" interval %zd ", mconf->interval);
  if (mconf->interval == NGX_ERROR || mconf->interval == 0) {
    mconf->interval = -1;
    return "invalid value" ;
  }

  /*获取共享内存大小*/
  mconf->shmsize = ngx_parse_size(&value[2]);
  if (mconf->shmsize == NGX_ERROR || mconf->shmsize == 0) {
    /*关闭限速功能*/
    mconf->interval = -1;
    return "invalid value";
  }


  DEBUG(" shmsize %zd ", mconf->shmsize);


  DEBUG(" module %p ", &ngx_http_restriction_module);


  if (mconf->shmsize < (ssize_t) (8 * ngx_pagesize)) {
    DEBUG("%p ,%s, %lu", cf,
          "shmsize is too small: ", mconf->shmsize);
    return NGX_CONF_ERROR;
  }


  /*申请共享内存*/
  ////**************shmsize过小，共享内存分配会失败，产生coredump
  shm_zone = ngx_shared_memory_add(cf, &name, mconf->shmsize
                                   , &ngx_http_restriction_module);

  DEBUG("shm_zone %p", shm_zone);

  if (shm_zone == NULL) {
    //申请失败，关闭限速功能
    DEBUG("shn_zone is NULL ");
    mconf->interval = -1 ;
    return NGX_CONF_ERROR ;
  }

  //共享内存分配成功后的回调方法
  shm_zone->init = ngx_http_restriction_shm_init ;
  shm_zone->data = mconf;

  DEBUG("end");

  return NGX_CONF_OK;

}




static ngx_int_t ngx_http_restriction_shm_init(ngx_shm_zone_t *shm_zone, void *data) {
  ngx_http_restriction_main_conf_t *conf;

  DEBUG("start");

  /*data可能为空，也可能是上次ngx_http_restriction_shm_init执行问后的shm_zone->data*/
  ngx_http_restriction_main_conf_t *oconf = data ;
  size_t       len;
  conf = (ngx_http_restriction_main_conf_t *)shm_zone->data;

  /*判断是否为nginx -s reload后，导致的初始化共享内存*/
  if (oconf) {
    /*
    本次共享内存不是新建的，将data指向上次在内存中创建的配置信息
    */
    conf->sh = oconf->sh ;
    conf->shpool = oconf->shpool;

    return NGX_OK ;
  }

  /*以前没创建过，重新创建*/

  /*shm.addr存放ngx_slab_pool_t首地址*/
  conf->shpool = (ngx_slab_pool_t * )shm_zone->shm.addr ;
  conf->sh = (ngx_http_restriction_shm_t*)ngx_slab_alloc(conf->shpool, sizeof(ngx_http_restriction_shm_t));

  if (conf->sh == NULL) {
    return NGX_ERROR ;
  }

  conf->shpool->data = conf->sh;


  /*初始化红黑树*/
  ngx_rbtree_init(&conf->sh->rbtree,
                  &conf->sh->sentinel,
                  ngx_http_restriction_rbtree_insert_value
                 );

  /*初始化淘汰队列*/
  ngx_queue_init(&conf->sh->queue);

  /*共享内存错误log的标示信息，便于区别*/
  char * bs =     " restriction slabe name " ;
  len = sizeof(bs) + shm_zone->shm.name.len ;

  conf->shpool->log_ctx = ngx_slab_alloc(conf->shpool, len);
  if (conf->shpool->log_ctx == NULL) {
    return NGX_ERROR ;
  }

  ngx_sprintf(conf->shpool->log_ctx, bs, &shm_zone->shm.name);

  DEBUG("end");
  return NGX_OK;

}




/*自定义红黑树插入函数*/
static void ngx_http_restriction_rbtree_insert_value(ngx_rbtree_node_t *root
    , ngx_rbtree_node_t *node
    , ngx_rbtree_node_t *sentinel) {


  DEBUG("start");


  ngx_rbtree_node_t **p ;
  ngx_http_restriction_node_t *res_node, *res_node_tmp ;

  for (;;) {
    /*寻找插入位置，即寻找插入节点的父节点*/

    if ( node->key < root->key ) {
      p = &root->left;
    } else if ( node->key > root->key ) {
      p = &root->right;
    } else {
      /* node->key == root->key */
      res_node = (ngx_http_restriction_node_t *) &node->data;
      res_node_tmp = (ngx_http_restriction_node_t *) &root->data;
      /*当key相等时，比较data字符串*/
      p = (ngx_memn2cmp(res_node->data, res_node_tmp->data, res_node->len, res_node_tmp->len) < 0) ? &root->left : &root->right;
    }

    /*找到哨兵节点才终止*/
    if (*p == sentinel) {
      break ;
    }

    root = *p; /*变换root节点，继续寻找*/

  }

  *p = node ;
  node->parent = root;
  node->left = sentinel ; /*新节点的左右节点都是哨兵节点*/
  node->right = sentinel ;
  ngx_rbt_red(node);/*必须设置当前节点为红色。有可能需要旋转，由ngx自动完成,颜色可能被重置*/

  DEBUG("end");

}















