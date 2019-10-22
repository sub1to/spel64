project "Dummy"
	uuid				"0ee8224f-9594-4b7b-9710-d60633f87643"
	kind				"SharedLib"
	characterset		"MBCS"
	
	buildoptions {
		"/Zc:threadSafeInit-",
	}

	files
	{
		"Dummy/**.inc",
		"Dummy/**.asm",
		"Dummy/**.cpp",
		"Dummy/**.h",
		"Dummy/**.rc",
	}	
	
	vpaths {
		["*"]	= { "Dummy" },
	}
	
	includedirs {
		"Dummy/",
	}
	
	libdirs {
		"Dummy/",
	}
		
	filter "configurations:Debug"
		defines { "DEBUG" }
		optimize "Off"
		symbols "On"
		
	filter "configurations:Dev"
		flags { "LinkTimeOptimization", "NoIncrementalLink" }
		optimize "Off"
		symbols "Off"
		
	filter "configurations:Release"
		flags { "LinkTimeOptimization", "NoIncrementalLink" }
		defines { "NDEBUG" }
		optimize "Full"
		symbols "Off"