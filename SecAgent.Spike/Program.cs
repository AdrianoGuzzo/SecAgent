using SecAgent.Spike;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.Configure<SpikeOptions>(builder.Configuration.GetSection("Spike"));
builder.Services.Configure<ClaudeOptions>(builder.Configuration.GetSection("Claude"));
builder.Services.AddHostedService<Worker>();
builder.Services.AddWindowsService(options => options.ServiceName = "SecAgentSpike");

var host = builder.Build();
host.Run();
