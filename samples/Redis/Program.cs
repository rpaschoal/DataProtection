﻿using System;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.DataProtection.Redis;
using StackExchange.Redis;

namespace Redis
{
    public class Program
    {
        public static void Main(string[] args)
        {
            // Connect
            var redis = ConnectionMultiplexer.Connect("localhost:6379");

            // Configure
            var serviceCollection = new ServiceCollection();
            serviceCollection.AddLogging();
            serviceCollection.AddDataProtection()
                .PersistKeysToRedis(redis, "DataProtection-Keys");

            var services = serviceCollection.BuildServiceProvider();
            var loggerFactory = services.GetService<ILoggerFactory>();
            loggerFactory.AddConsole(LogLevel.Trace);

            // Run a sample payload
            var protector = services.GetDataProtector("sample-purpose");
            var protectedData = protector.Protect("Hello world!");
            Console.WriteLine(protectedData);
        }
    }
}