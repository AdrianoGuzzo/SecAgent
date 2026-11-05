using SecAgent.Service;

// Composição em ServiceRegistration (testada); aqui só o host.
var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddSecAgentService(builder.Configuration);
builder.Services.AddWindowsService(o => o.ServiceName = "SecAgent");

var host = builder.Build();
host.Run();
