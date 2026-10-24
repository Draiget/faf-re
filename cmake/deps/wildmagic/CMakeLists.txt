# Wild Magic 3.8: Foundation, Dx9Renderer and Dx9Application static libraries.
#
# Mirrors the FAF project files dependencies/WildMagic3p8/{Foundation/
# Foundation.vcxproj, Renderers/Dx9Renderer/Dx9Renderer.vcxproj,
# Applications/Dx9Application.vcxproj} (main.vcxproj's ProjectReferences):
# same sources, WIN32;NDEBUG;_LIB, C++20 without /permissive-, /EHsc. The
# tree is shared and read-only; the libraries are built here.

set(WM3_ROOT "${FAF_DEPENDENCIES_DIR}/WildMagic3p8")
set(WM3_FOUNDATION "${WM3_ROOT}/Foundation")
set(WM3_FOUNDATION_SUBDIRS
  Approximation Collision Containment Controllers Curves Detail Distance Effects
  ImageAnalysis Interpolation Intersection Math Meshes Miscellaneous Numerics
  ObjectSystem Physics RationalArithmetic SceneGraph Shaders SharedArrays Sorting
  Surfaces System Terrain Tessellation)
set(WM3_FOUNDATION_INCLUDES "${WM3_FOUNDATION}")
foreach(_dir IN LISTS WM3_FOUNDATION_SUBDIRS)
  list(APPEND WM3_FOUNDATION_INCLUDES "${WM3_FOUNDATION}/${_dir}")
endforeach()

add_library(faf_wm3_build_flags INTERFACE)
target_compile_definitions(faf_wm3_build_flags INTERFACE WIN32 NDEBUG _LIB)
target_compile_options(faf_wm3_build_flags INTERFACE /EHsc /W0)
target_link_libraries(faf_wm3_build_flags INTERFACE faf_codegen)

# --- Foundation ------------------------------------------------------------------
set(WM3_FOUNDATION_SOURCES
  Approximation/Wm3ApprCircleFit2.cpp Approximation/Wm3ApprCylinderFit3.cpp
  Approximation/Wm3ApprEllipseFit2.cpp Approximation/Wm3ApprEllipsoidFit3.cpp
  Approximation/Wm3ApprGaussPointsFit2.cpp Approximation/Wm3ApprGaussPointsFit3.cpp
  Approximation/Wm3ApprLineFit2.cpp Approximation/Wm3ApprLineFit3.cpp
  Approximation/Wm3ApprParaboloidFit3.cpp Approximation/Wm3ApprPlaneFit3.cpp
  Approximation/Wm3ApprPolyFit2.cpp Approximation/Wm3ApprPolyFit3.cpp
  Approximation/Wm3ApprPolyFit4.cpp Approximation/Wm3ApprQuadraticFit2.cpp
  Approximation/Wm3ApprQuadraticFit3.cpp Approximation/Wm3ApprSphereFit3.cpp
  Collision/Wm3BoundingVolumeTree.cpp Collision/Wm3BoxBVTree.cpp
  Collision/Wm3CollisionGroup.cpp Collision/Wm3CollisionRecord.cpp
  Collision/Wm3SphereBVTree.cpp
  Containment/Wm3ContBox2.cpp Containment/Wm3ContBox3.cpp
  Containment/Wm3ContCapsule3.cpp Containment/Wm3ContCircle2.cpp
  Containment/Wm3ContCylinder3.cpp Containment/Wm3ContEllipse2.cpp
  Containment/Wm3ContEllipsoid3.cpp Containment/Wm3ContLozenge3.cpp
  Containment/Wm3ContPointInPolygon2.cpp Containment/Wm3ContScribeCircle2.cpp
  Containment/Wm3ContScribeCircle3Sphere3.cpp Containment/Wm3ContSeparatePoints2.cpp
  Containment/Wm3ContSeparatePoints3.cpp Containment/Wm3ContSphere3.cpp
  Containment/Wm3ConvexHull.cpp Containment/Wm3ConvexHull1.cpp
  Containment/Wm3ConvexHull2.cpp Containment/Wm3ConvexHull3.cpp
  Containment/Wm3HullEdge2.cpp Containment/Wm3HullTriangle3.cpp
  Controllers/Wm3Controller.cpp Controllers/Wm3IKController.cpp
  Controllers/Wm3IKGoal.cpp Controllers/Wm3IKJoint.cpp
  Controllers/Wm3KeyframeController.cpp Controllers/Wm3MorphController.cpp
  Controllers/Wm3ParticleController.cpp Controllers/Wm3PointController.cpp
  Controllers/Wm3SkinController.cpp
  Curves/Wm3BezierCurve2.cpp Curves/Wm3BezierCurve3.cpp Curves/Wm3BSplineBasis.cpp
  Curves/Wm3BSplineCurve2.cpp Curves/Wm3BSplineCurve3.cpp Curves/Wm3BSplineFit.cpp
  Curves/Wm3BSplineFitBasis.cpp Curves/Wm3BSplineGeodesic.cpp
  Curves/Wm3BSplineReduction.cpp Curves/Wm3CubicPolynomialCurve2.cpp
  Curves/Wm3CubicPolynomialCurve3.cpp Curves/Wm3Curve2.cpp Curves/Wm3Curve3.cpp
  Curves/Wm3CurveMesh.cpp Curves/Wm3CurveSegment.cpp Curves/Wm3EllipsoidGeodesic.cpp
  Curves/Wm3MultipleCurve2.cpp Curves/Wm3MultipleCurve3.cpp Curves/Wm3NaturalSpline2.cpp
  Curves/Wm3NaturalSpline3.cpp Curves/Wm3NURBSCurve2.cpp Curves/Wm3NURBSCurve3.cpp
  Curves/Wm3PolynomialCurve2.cpp Curves/Wm3PolynomialCurve3.cpp
  Curves/Wm3RiemannianGeodesic.cpp Curves/Wm3SingleCurve2.cpp Curves/Wm3SingleCurve3.cpp
  Curves/Wm3TCBSpline2.cpp Curves/Wm3TCBSpline3.cpp
  Detail/Wm3BillboardNode.cpp Detail/Wm3ClodMesh.cpp Detail/Wm3CollapseRecord.cpp
  Detail/Wm3CreateClodMesh.cpp Detail/Wm3DlodNode.cpp Detail/Wm3SwitchNode.cpp
  Distance/Wm3Distance.cpp Distance/Wm3DistCircle3Circle3.cpp
  Distance/Wm3DistLine2Line2.cpp Distance/Wm3DistLine2Ray2.cpp
  Distance/Wm3DistLine2Segment2.cpp Distance/Wm3DistLine3Box3.cpp
  Distance/Wm3DistLine3Circle3.cpp Distance/Wm3DistLine3Line3.cpp
  Distance/Wm3DistLine3Ray3.cpp Distance/Wm3DistLine3Rectangle3.cpp
  Distance/Wm3DistLine3Segment3.cpp Distance/Wm3DistLine3Triangle3.cpp
  Distance/Wm3DistRay2Ray2.cpp Distance/Wm3DistRay2Segment2.cpp
  Distance/Wm3DistRay3Box3.cpp Distance/Wm3DistRay3Ray3.cpp
  Distance/Wm3DistRay3Rectangle3.cpp Distance/Wm3DistRay3Segment3.cpp
  Distance/Wm3DistRay3Triangle3.cpp Distance/Wm3DistRectangle3Rectangle3.cpp
  Distance/Wm3DistSegment2Segment2.cpp Distance/Wm3DistSegment3Box3.cpp
  Distance/Wm3DistSegment3Rectangle3.cpp Distance/Wm3DistSegment3Segment3.cpp
  Distance/Wm3DistSegment3Triangle3.cpp Distance/Wm3DistTriangle3Rectangle3.cpp
  Distance/Wm3DistTriangle3Triangle3.cpp Distance/Wm3DistVector2Box2.cpp
  Distance/Wm3DistVector2Ellipse2.cpp Distance/Wm3DistVector2Line2.cpp
  Distance/Wm3DistVector2Quadratic2.cpp Distance/Wm3DistVector2Ray2.cpp
  Distance/Wm3DistVector2Segment2.cpp Distance/Wm3DistVector3Box3.cpp
  Distance/Wm3DistVector3Circle3.cpp Distance/Wm3DistVector3Ellipsoid3.cpp
  Distance/Wm3DistVector3Frustum3.cpp Distance/Wm3DistVector3Line3.cpp
  Distance/Wm3DistVector3Plane3.cpp Distance/Wm3DistVector3Quadratic3.cpp
  Distance/Wm3DistVector3Ray3.cpp Distance/Wm3DistVector3Rectangle3.cpp
  Distance/Wm3DistVector3Segment3.cpp Distance/Wm3DistVector3Tetrahedron3.cpp
  Distance/Wm3DistVector3Triangle3.cpp
  Effects/Wm3BumpMapEffect.cpp Effects/Wm3DarkMapEffect.cpp Effects/Wm3Effect.cpp
  Effects/Wm3EnvironmentMapEffect.cpp Effects/Wm3GlossMapEffect.cpp
  Effects/Wm3LightMapEffect.cpp Effects/Wm3PlanarReflectionEffect.cpp
  Effects/Wm3PlanarShadowEffect.cpp Effects/Wm3ProjectedTextureEffect.cpp
  Effects/Wm3TextureEffect.cpp Effects/Wm3VertexColorEffect.cpp
  ImageAnalysis/Wm3Binary2D.cpp ImageAnalysis/Wm3Binary3D.cpp
  ImageAnalysis/Wm3Element.cpp ImageAnalysis/Wm3ExtractSurfaceCubes.cpp
  ImageAnalysis/Wm3ExtractSurfaceTetra.cpp ImageAnalysis/Wm3FastBlur.cpp
  ImageAnalysis/Wm3ImageConvert.cpp ImageAnalysis/Wm3Images.cpp
  ImageAnalysis/Wm3Lattice.cpp ImageAnalysis/Wm3RasterDrawing.cpp
  Interpolation/Wm3IntpAkima1.cpp Interpolation/Wm3IntpAkimaNonuniform1.cpp
  Interpolation/Wm3IntpAkimaUniform1.cpp Interpolation/Wm3IntpAkimaUniform2.cpp
  Interpolation/Wm3IntpAkimaUniform3.cpp Interpolation/Wm3IntpBicubic2.cpp
  Interpolation/Wm3IntpBilinear2.cpp Interpolation/Wm3IntpBSplineUniform.cpp
  Interpolation/Wm3IntpBSplineUniform1.cpp Interpolation/Wm3IntpBSplineUniform2.cpp
  Interpolation/Wm3IntpBSplineUniform3.cpp Interpolation/Wm3IntpBSplineUniform4.cpp
  Interpolation/Wm3IntpBSplineUniformN.cpp Interpolation/Wm3IntpLinearNonuniform2.cpp
  Interpolation/Wm3IntpLinearNonuniform3.cpp Interpolation/Wm3IntpQdrNonuniform2.cpp
  Interpolation/Wm3IntpSphere2.cpp Interpolation/Wm3IntpThinPlateSpline2.cpp
  Interpolation/Wm3IntpThinPlateSpline3.cpp Interpolation/Wm3IntpTricubic3.cpp
  Interpolation/Wm3IntpTrilinear3.cpp Interpolation/Wm3IntpVectorField2.cpp
  Intersection/Wm3Intersector.cpp Intersection/Wm3Intersector1.cpp
  Intersection/Wm3IntrArc2Arc2.cpp Intersection/Wm3IntrArc2Circle2.cpp
  Intersection/Wm3IntrBox2Box2.cpp Intersection/Wm3IntrBox2Circle2.cpp
  Intersection/Wm3IntrBox3Box3.cpp Intersection/Wm3IntrBox3Frustum3.cpp
  Intersection/Wm3IntrBox3Sphere3.cpp Intersection/Wm3IntrCapsule3Capsule3.cpp
  Intersection/Wm3IntrCircle2Circle2.cpp Intersection/Wm3IntrCircle3Plane3.cpp
  Intersection/Wm3IntrEllipse2Ellipse2.cpp Intersection/Wm3IntrLinComp2LinComp2.cpp
  Intersection/Wm3IntrLinComp2Triangle2.cpp Intersection/Wm3IntrLine2Arc2.cpp
  Intersection/Wm3IntrLine2Box2.cpp Intersection/Wm3IntrLine2Circle2.cpp
  Intersection/Wm3IntrLine3Box3.cpp Intersection/Wm3IntrLine3Capsule3.cpp
  Intersection/Wm3IntrLine3Cone3.cpp Intersection/Wm3IntrLine3Cylinder3.cpp
  Intersection/Wm3IntrLine3Ellipsoid3.cpp Intersection/Wm3IntrLine3Lozenge3.cpp
  Intersection/Wm3IntrLine3Plane3.cpp Intersection/Wm3IntrLine3Sphere3.cpp
  Intersection/Wm3IntrLine3Torus3.cpp Intersection/Wm3IntrLine3Triangle3.cpp
  Intersection/Wm3IntrLozenge3Lozenge3.cpp Intersection/Wm3IntrPlane3Box3.cpp
  Intersection/Wm3IntrPlane3Capsule3.cpp Intersection/Wm3IntrPlane3Cylinder3.cpp
  Intersection/Wm3IntrPlane3Ellipsoid3.cpp Intersection/Wm3IntrPlane3Lozenge3.cpp
  Intersection/Wm3IntrPlane3Plane3.cpp Intersection/Wm3IntrPlane3Sphere3.cpp
  Intersection/Wm3IntrPlane3Triangle3.cpp Intersection/Wm3IntrRay2Arc2.cpp
  Intersection/Wm3IntrRay2Box2.cpp Intersection/Wm3IntrRay2Circle2.cpp
  Intersection/Wm3IntrRay3Box3.cpp Intersection/Wm3IntrRay3Capsule3.cpp
  Intersection/Wm3IntrRay3Cylinder3.cpp Intersection/Wm3IntrRay3Ellipsoid3.cpp
  Intersection/Wm3IntrRay3Lozenge3.cpp Intersection/Wm3IntrRay3Plane3.cpp
  Intersection/Wm3IntrRay3Sphere3.cpp Intersection/Wm3IntrRay3Triangle3.cpp
  Intersection/Wm3IntrSegment2Arc2.cpp Intersection/Wm3IntrSegment2Box2.cpp
  Intersection/Wm3IntrSegment2Circle2.cpp Intersection/Wm3IntrSegment3Box3.cpp
  Intersection/Wm3IntrSegment3Capsule3.cpp Intersection/Wm3IntrSegment3Cylinder3.cpp
  Intersection/Wm3IntrSegment3Ellipsoid3.cpp Intersection/Wm3IntrSegment3Lozenge3.cpp
  Intersection/Wm3IntrSegment3Plane3.cpp Intersection/Wm3IntrSegment3Sphere3.cpp
  Intersection/Wm3IntrSegment3Triangle3.cpp Intersection/Wm3IntrSphere3Cone3.cpp
  Intersection/Wm3IntrSphere3Frustum3.cpp Intersection/Wm3IntrSphere3Sphere3.cpp
  Intersection/Wm3IntrTetrahedron3Tetrahedron3.cpp
  Intersection/Wm3IntrTriangle2Triangle2.cpp Intersection/Wm3IntrTriangle3Cone3.cpp
  Intersection/Wm3IntrTriangle3Triangle3.cpp
  Math/Wm3ColorRGB.cpp Math/Wm3ColorRGBA.cpp Math/Wm3Math.cpp Math/Wm3Matrix2.cpp
  Math/Wm3Matrix3.cpp Math/Wm3Matrix4.cpp Math/Wm3Quaternion.cpp Math/Wm3Vector2.cpp
  Math/Wm3Vector3.cpp Math/Wm3Vector4.cpp
  Meshes/Wm3BasicMesh.cpp Meshes/Wm3ConformalMap.cpp Meshes/Wm3ETManifoldMesh.cpp
  Meshes/Wm3ETNonmanifoldMesh.cpp Meshes/Wm3MeshCurvature.cpp Meshes/Wm3MeshSmoother.cpp
  Meshes/Wm3VEManifoldMesh.cpp Meshes/Wm3VETMesh.cpp
  Miscellaneous/Wm3GridGraph2.cpp Miscellaneous/Wm3NormalCompression.cpp
  Miscellaneous/Wm3PerspProjEllipsoid.cpp Miscellaneous/Wm3QuadToQuadTransforms.cpp
  Miscellaneous/Wm3RandomHypersphere.cpp Miscellaneous/Wm3TangentsToCircles.cpp
  Numerics/Wm3Bisect1.cpp Numerics/Wm3Bisect2.cpp Numerics/Wm3Bisect3.cpp
  Numerics/Wm3Eigen.cpp Numerics/Wm3Integrate1.cpp Numerics/Wm3LinearSystem.cpp
  Numerics/Wm3Minimize1.cpp Numerics/Wm3MinimizeN.cpp Numerics/Wm3OdeEuler.cpp
  Numerics/Wm3OdeImplicitEuler.cpp Numerics/Wm3OdeMidpoint.cpp
  Numerics/Wm3OdeRungeKutta4.cpp Numerics/Wm3OdeSolver.cpp
  Numerics/Wm3PolynomialRoots.cpp
  ObjectSystem/Wm3ImageVersion.cpp ObjectSystem/Wm3Main.cpp ObjectSystem/Wm3Object.cpp
  ObjectSystem/Wm3Rtti.cpp ObjectSystem/Wm3Stream.cpp ObjectSystem/Wm3StreamVersion.cpp
  ObjectSystem/Wm3StringTree.cpp
  Physics/Wm3BoxSurface.cpp Physics/Wm3BSplineVolume.cpp Physics/Wm3ExtremalQuery3.cpp
  Physics/Wm3ExtremalQuery3BSP.cpp Physics/Wm3ExtremalQuery3PRJ.cpp
  Physics/Wm3IntersectingBoxes.cpp Physics/Wm3IntersectingIntervals.cpp
  Physics/Wm3IntersectingRectangles.cpp Physics/Wm3LCPPolyDist.cpp
  Physics/Wm3LCPSolver.cpp Physics/Wm3MassSpringArbitrary.cpp
  Physics/Wm3MassSpringCurve.cpp Physics/Wm3MassSpringSurface.cpp
  Physics/Wm3MassSpringVolume.cpp Physics/Wm3ParticleSystem.cpp
  Physics/Wm3PolyhedralMassProperties.cpp Physics/Wm3RectangleSurface.cpp
  Physics/Wm3RevolutionSurface.cpp Physics/Wm3RigidBody.cpp Physics/Wm3TubeSurface.cpp
  SceneGraph/Wm3AlphaState.cpp SceneGraph/Wm3BindInfo.cpp
  SceneGraph/Wm3BoundingVolume.cpp SceneGraph/Wm3BoxBV.cpp SceneGraph/Wm3Camera.cpp
  SceneGraph/Wm3CullState.cpp SceneGraph/Wm3DitherState.cpp SceneGraph/Wm3FogState.cpp
  SceneGraph/Wm3Geometry.cpp SceneGraph/Wm3GlobalState.cpp SceneGraph/Wm3Image.cpp
  SceneGraph/Wm3Light.cpp SceneGraph/Wm3MaterialState.cpp SceneGraph/Wm3Node.cpp
  SceneGraph/Wm3Particles.cpp SceneGraph/Wm3PBuffer.cpp SceneGraph/Wm3Polyline.cpp
  SceneGraph/Wm3Polypoint.cpp SceneGraph/Wm3Renderer.cpp SceneGraph/Wm3ScreenPolygon.cpp
  SceneGraph/Wm3ShadeState.cpp SceneGraph/Wm3Spatial.cpp SceneGraph/Wm3SphereBV.cpp
  SceneGraph/Wm3StandardMesh.cpp SceneGraph/Wm3Texture.cpp
  SceneGraph/Wm3Transformation.cpp SceneGraph/Wm3TriMesh.cpp
  SceneGraph/Wm3WireframeState.cpp SceneGraph/Wm3ZBufferState.cpp
  Shaders/Wm3PixelShader.cpp Shaders/Wm3Shader.cpp Shaders/Wm3ShaderConstant.cpp
  Shaders/Wm3ShaderEffect.cpp Shaders/Wm3VertexShader.cpp
  SharedArrays/Wm3CachedColorRGBAArray.cpp SharedArrays/Wm3CachedColorRGBArray.cpp
  SharedArrays/Wm3CachedIntArray.cpp SharedArrays/Wm3CachedVector2fArray.cpp
  SharedArrays/Wm3CachedVector3fArray.cpp SharedArrays/Wm3ColorRGBAArray.cpp
  SharedArrays/Wm3ColorRGBArray.cpp SharedArrays/Wm3DoubleArray.cpp
  SharedArrays/Wm3FloatArray.cpp SharedArrays/Wm3IntArray.cpp
  SharedArrays/Wm3Matrix2Array.cpp SharedArrays/Wm3Matrix3Array.cpp
  SharedArrays/Wm3Matrix4Array.cpp SharedArrays/Wm3Plane3Array.cpp
  SharedArrays/Wm3QuaternionArray.cpp SharedArrays/Wm3Vector2Array.cpp
  SharedArrays/Wm3Vector3Array.cpp SharedArrays/Wm3Vector4Array.cpp
  Sorting/Wm3BspNode.cpp Sorting/Wm3ConvexRegion.cpp Sorting/Wm3ConvexRegionManager.cpp
  Sorting/Wm3Portal.cpp
  Surfaces/Wm3BSplineRectangle.cpp Surfaces/Wm3ImplicitSurface.cpp
  Surfaces/Wm3NURBSRectangle.cpp Surfaces/Wm3ParametricSurface.cpp
  Surfaces/Wm3QuadricSurface.cpp Surfaces/Wm3Surface.cpp Surfaces/Wm3SurfaceMesh.cpp
  Surfaces/Wm3SurfacePatch.cpp
  System/Wm3Memory.cpp System/Wm3String.cpp System/Wm3System.cpp
  Terrain/Wm3ClodTerrain.cpp Terrain/Wm3ClodTerrainBlock.cpp
  Terrain/Wm3ClodTerrainPage.cpp Terrain/Wm3ClodTerrainVertex.cpp Terrain/Wm3Terrain.cpp
  Terrain/Wm3TerrainPage.cpp
  Tessellation/Wm3Delaunay.cpp Tessellation/Wm3Delaunay1.cpp
  Tessellation/Wm3Delaunay2.cpp Tessellation/Wm3Delaunay3.cpp
  Tessellation/Wm3DelPolygonEdge.cpp Tessellation/Wm3DelPolyhedronFace.cpp
  Tessellation/Wm3DelTetrahedron.cpp Tessellation/Wm3DelTriangle.cpp
  Tessellation/Wm3TriangulateEC.cpp
)
# Left out: six sources clang rejects where cl accepts them (an explicit
# specialisation of a static data member after its first use, and
# `LCPSolver::LCPSolver` used as a type name). Nothing in the engine or in the
# other two libraries references them, so the link pulls the same objects
# without them.
list(REMOVE_ITEM WM3_FOUNDATION_SOURCES
  Interpolation/Wm3IntpBicubic2.cpp Interpolation/Wm3IntpBilinear2.cpp
  Interpolation/Wm3IntpTricubic3.cpp Interpolation/Wm3IntpTrilinear3.cpp
  Miscellaneous/Wm3GridGraph2.cpp Physics/Wm3LCPPolyDist.cpp)
list(TRANSFORM WM3_FOUNDATION_SOURCES PREPEND "${WM3_FOUNDATION}/")
add_library(Wm3Foundation STATIC ${WM3_FOUNDATION_SOURCES})
target_include_directories(Wm3Foundation PUBLIC ${WM3_FOUNDATION_INCLUDES})
target_link_libraries(Wm3Foundation PRIVATE faf_wm3_build_flags)

# --- Dx9Renderer -----------------------------------------------------------------
set(WM3_DX9RENDERER "${WM3_ROOT}/Renderers/Dx9Renderer")
add_library(Wm3Dx9Renderer STATIC
  ${WM3_DX9RENDERER}/Wm3Dx9AlphaState.cpp ${WM3_DX9RENDERER}/Wm3Dx9ApplyParameters.cpp
  ${WM3_DX9RENDERER}/Wm3Dx9BumpMap.cpp ${WM3_DX9RENDERER}/Wm3Dx9CullState.cpp
  ${WM3_DX9RENDERER}/Wm3Dx9DitherState.cpp ${WM3_DX9RENDERER}/Wm3Dx9DrawText.cpp
  ${WM3_DX9RENDERER}/Wm3Dx9EnvironmentMap.cpp ${WM3_DX9RENDERER}/Wm3Dx9FogState.cpp
  ${WM3_DX9RENDERER}/Wm3Dx9GlossMap.cpp ${WM3_DX9RENDERER}/Wm3Dx9MaterialState.cpp
  ${WM3_DX9RENDERER}/Wm3Dx9PBuffer.cpp ${WM3_DX9RENDERER}/Wm3Dx9PlanarReflection.cpp
  ${WM3_DX9RENDERER}/Wm3Dx9PlanarShadow.cpp ${WM3_DX9RENDERER}/Wm3Dx9ProjectedTexture.cpp
  ${WM3_DX9RENDERER}/Wm3Dx9Renderer.cpp ${WM3_DX9RENDERER}/Wm3Dx9ShadeState.cpp
  ${WM3_DX9RENDERER}/Wm3Dx9Texture.cpp ${WM3_DX9RENDERER}/Wm3Dx9WireframeState.cpp
  ${WM3_DX9RENDERER}/Wm3Dx9ZBufferState.cpp)
# The project lists $(DXSDK_DIR)Include as an ordinary include directory, so
# here the DirectX SDK's d3d9.h comes before the Windows SDK's.
target_include_directories(Wm3Dx9Renderer
  PUBLIC "${WM3_DX9RENDERER}"
  PRIVATE "${FAF_DXSDK_DIR}/Include")
target_link_libraries(Wm3Dx9Renderer PUBLIC Wm3Foundation PRIVATE faf_wm3_build_flags)

# --- Dx9Application --------------------------------------------------------------
set(WM3_APPLICATIONS "${WM3_ROOT}/Applications")
add_library(Wm3Dx9Application STATIC
  ${WM3_APPLICATIONS}/Wm3Application.cpp ${WM3_APPLICATIONS}/Wm3Command.cpp
  ${WM3_APPLICATIONS}/Wm3ConsoleApplication.cpp ${WM3_APPLICATIONS}/Wm3Dx9Application.cpp
  ${WM3_APPLICATIONS}/Wm3WindowApplication.cpp ${WM3_APPLICATIONS}/Wm3WindowApplication2.cpp
  ${WM3_APPLICATIONS}/Wm3WindowApplication3.cpp)
target_include_directories(Wm3Dx9Application
  PUBLIC "${WM3_APPLICATIONS}"
  PRIVATE "${FAF_DXSDK_DIR}/Include")
target_link_libraries(Wm3Dx9Application PUBLIC Wm3Dx9Renderer PRIVATE faf_wm3_build_flags)

set_target_properties(Wm3Foundation Wm3Dx9Renderer Wm3Dx9Application PROPERTIES FOLDER "dependencies/WildMagic")
