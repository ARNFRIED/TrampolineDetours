#pragma once
#include <d3d9.h>
#include <d3dx9math.h>

struct CameraInfo
{
	int vtable;
	int field2;
	D3DXVECTOR3 Position;
	float fViewMat[9];
	float NearPlane;
	float FarPlane;
	float FieldOfView;
	float Aspect;
};

inline auto GetActiveCamera()
{
	auto world_frame = *(int*)(0x00B4B2BC);

	if (world_frame)
		return *(CameraInfo**)(world_frame + 0x65B8);	/*WorldFrame + ActiveCamera*/
	else
		return (CameraInfo*)0;
}

inline auto Projection()
{
	auto cam = GetActiveCamera();
	D3DXMATRIX matrix{};
	D3DXMatrixPerspectiveFovLH(&matrix, cam->FieldOfView * 0.6f, cam->Aspect, cam->NearPlane, cam->FarPlane);
	return matrix;
}

int GetVirtualFuncAddr(int addr, int offset) { return addr ? *(int*)(*(int*)addr + 4 * offset) : 0; }

inline auto Forward()
{
	D3DXVECTOR3 res{};
	auto cam = GetActiveCamera();
	if (cam)
	{
		int funcaddr = GetVirtualFuncAddr((int)cam, 1);
		((D3DXVECTOR3*(__thiscall*)(CameraInfo*, D3DXVECTOR3*))(funcaddr))(cam, &res);
	}
	return res;
}

inline auto View()
{
	auto cam = GetActiveCamera();
	auto eye = cam->Position;
	auto at = eye + Forward();
	D3DXVECTOR3 up = { 0, 0, 1 };
	D3DXMATRIX matrix{};
	D3DXMatrixLookAtRH(&matrix, &eye, &at, &up);
	return matrix;
}