from platform import system

import redis

isWindows = system() == "Windows"

""" Wrapper around redis

You need to install redis

Ex. for windows
    https://github.com/MicrosoftArchive/redis/releases

And install redis package (pip install redis)
"""


class Redis(object):
    _redis_client = None
    _pools = {}
    db = 0

    # ===================
    # Private methods
    # ===================

    @staticmethod
    def _get_params(db, decode_responses=True):
        params = {"host": "localhost", "port": 6379, "db": db}
        params["decode_responses"] = decode_responses

        return params

    @classmethod
    def _pool_client(cls, db, decode_responses=True):
        """ returns a client using a shared connection pool for any one db"""
        pool = cls._pools.get((db, decode_responses), None)
        if not pool:
            params = Redis._get_params(db, decode_responses=decode_responses)
            cls._pools[(db, decode_responses)] = pool = redis.ConnectionPool(**params)

        params = {"connection_pool": pool}

        if not isWindows:
            params.update(unix_socket_path='/tmp/redis.sock')

        return redis.Redis(**params)

    @classmethod
    def _get_client(cls):
        if cls._redis_client is None:
            print("Getting redis client")
            cls._redis_client = Redis._pool_client(cls.db, decode_responses=True)

        return cls._redis_client

    # ===================
    # Public method
    # ===================

    @classmethod
    def flush_db(cls):
        """ Flush database (i.e. delete all entries in redis database)
        """
        Redis._get_client().flushdb()

    # ===================================
    # Public method for key value store
    # ===================================

    @classmethod
    def get_value(cls, key):
        """ Read value from key value store
        """
        client = cls._get_client()
        value = client.get(key)

        return value

    @classmethod
    def set_value(cls, key, value, expiration=None):
        """ Set value to key value store
        """
        print("Setting value = %s for key = %s" % (value, key))
        client = cls._get_client()
        client.set(key, value,ex=expiration)


    @classmethod
    def add_by_range(cls,key,score,value):
        client = cls._get_client()
        mapping = {str(value):score}
        client.zadd(key,mapping)



    @classmethod
    def get_by_range(cls,key,score):
        client = cls._get_client()
        result = client.zrangebyscore(key,-1,score)
        #client.pipeline().zremrangebyscore()
        return result


    @classmethod
    def redis_pipeline(cls):
        client = cls._get_client()
        return client.pipeline()

    # ===================================
    # Public method for queues
    # ===================================

    @classmethod
    def rpush(cls, queue_name=None, value=None):
        cls._get_client().rpush(queue_name, value)

    @classmethod
    def rpop(cls, queue_name=None):
        # https://redis.io/commands/rpop
        return cls._get_client().rpop(queue_name)

    @classmethod
    def brpop(cls, queue_name=None):
        # https://redis.io/commands/brpop
        return cls._get_client().brpop(queue_name)