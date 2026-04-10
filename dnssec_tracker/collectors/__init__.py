"""Collectors: long-running tasks that observe a data source and emit
``Event`` rows into the database.

Every collector inherits :class:`base.Collector`. The ``lifespan`` of the
FastAPI app will construct the enabled collectors from config, start
them as asyncio tasks, and cancel them at shutdown.
"""
